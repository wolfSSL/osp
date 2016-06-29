/*
 * eap-tls.c - EAP-TLS implementation for PPP
 *
 * Copyright (c) Beniamino Galvani 2005 All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "pppd.h"
#include "eap.h"
#include "eap-tls.h"
#include "fsm.h"
#include "lcp.h"
#include "pathnames.h"

/* The openssl configuration file and engines can be loaded only once */
static CONF   *ssl_config  = NULL;
static ENGINE *cert_engine = NULL;
static ENGINE *pkey_engine = NULL;

#ifdef MPPE

/*
 * TLS PRF from RFC 2246
 */
static void P_hash(const EVP_MD *evp_md,
		   const unsigned char *secret, unsigned int secret_len,
		   const unsigned char *seed,   unsigned int seed_len,
		   unsigned char *out, unsigned int out_len)
{
	HMAC_CTX ctx_a, ctx_out;
	unsigned char a[HMAC_MAX_MD_CBLOCK];
	unsigned int size;

	HMAC_CTX_init(&ctx_a);
	HMAC_CTX_init(&ctx_out);
	HMAC_Init_ex(&ctx_a, secret, secret_len, evp_md, NULL);
	HMAC_Init_ex(&ctx_out, secret, secret_len, evp_md, NULL);

	size = HMAC_size(&ctx_out);

	/* Calculate A(1) */
	HMAC_Update(&ctx_a, seed, seed_len);
	HMAC_Final(&ctx_a, a, NULL);

	while (1) {
		/* Calculate next part of output */
		HMAC_Update(&ctx_out, a, size);
		HMAC_Update(&ctx_out, seed, seed_len);

		/* Check if last part */
		if (out_len < size) {
			HMAC_Final(&ctx_out, a, NULL);
			memcpy(out, a, out_len);
			break;
		}

		/* Place digest in output buffer */
		HMAC_Final(&ctx_out, out, NULL);
		HMAC_Init_ex(&ctx_out, NULL, 0, NULL, NULL);
		out += size;
		out_len -= size;

		/* Calculate next A(i) */
		HMAC_Init_ex(&ctx_a, NULL, 0, NULL, NULL);
		HMAC_Update(&ctx_a, a, size);
		HMAC_Final(&ctx_a, a, NULL);
	}

	HMAC_CTX_cleanup(&ctx_a);
	HMAC_CTX_cleanup(&ctx_out);
	memset(a, 0, sizeof(a));
}

static void PRF(const unsigned char *secret, unsigned int secret_len,
		const unsigned char *seed,   unsigned int seed_len,
		unsigned char *out, unsigned char *buf, unsigned int out_len)
{
        unsigned int i;
        unsigned int len = (secret_len + 1) / 2;
	const unsigned char *s1 = secret;
	const unsigned char *s2 = secret + (secret_len - len);

	P_hash(EVP_md5(),  s1, len, seed, seed_len, out, out_len);
	P_hash(EVP_sha1(), s2, len, seed, seed_len, buf, out_len);

	for (i=0; i < out_len; i++) {
	        out[i] ^= buf[i];
	}
}

#define EAPTLS_MPPE_KEY_LEN     32

/*
 *  Generate keys according to RFC 2716 and add to reply
 */
void eaptls_gen_mppe_keys(struct eaptls_session *ets, const char *prf_label,
                          int client)
{
    unsigned char out[4*EAPTLS_MPPE_KEY_LEN], buf[4*EAPTLS_MPPE_KEY_LEN];
    unsigned char seed[64 + 2*SSL3_RANDOM_SIZE];
    unsigned char *p = seed;
	SSL			  *s = ets->ssl;
    size_t prf_size;

    prf_size = strlen(prf_label);

    memcpy(p, prf_label, prf_size);
    p += prf_size;

    memcpy(p, s->s3->client_random, SSL3_RANDOM_SIZE);
    p += SSL3_RANDOM_SIZE;
    prf_size += SSL3_RANDOM_SIZE;

    memcpy(p, s->s3->server_random, SSL3_RANDOM_SIZE);
    prf_size += SSL3_RANDOM_SIZE;

    PRF(s->session->master_key, s->session->master_key_length,
        seed, prf_size, out, buf, sizeof(out));

    /* 
     * We now have the master send and receive keys.
     * From these, generate the session send and receive keys.
     * (see RFC3079 / draft-ietf-pppext-mppe-keys-03.txt for details)
     */
    if (client)
    {
	    p = out;
		BCOPY( p, mppe_send_key, sizeof(mppe_send_key) );
		p += EAPTLS_MPPE_KEY_LEN;
    	BCOPY( p, mppe_recv_key, sizeof(mppe_recv_key) );
    }
    else
    {
	    p = out;
    	BCOPY( p, mppe_recv_key, sizeof(mppe_recv_key) );
		p += EAPTLS_MPPE_KEY_LEN;
		BCOPY( p, mppe_send_key, sizeof(mppe_send_key) );
    }

    mppe_keys_set = 1;
}

#endif

void log_ssl_errors( void )
{
	unsigned long ssl_err = ERR_get_error();

    if (ssl_err != 0)
		dbglog("EAP-TLS SSL error stack:");
	while (ssl_err != 0) {
		dbglog( ERR_error_string( ssl_err, NULL ) );
		ssl_err = ERR_get_error();
	}
}


int password_callback (char *buf, int size, int rwflag, void *u)
{
	if (buf)
	{
		strncpy (buf, passwd, size);
		return strlen (buf);
	}
	return 0;
}


CONF *eaptls_ssl_load_config( void )
{
    CONF        *config;
    int          ret_code;
    long         error_line = 33;

    config = NCONF_new( NULL );
	dbglog( "Loading OpenSSL config file" );
    ret_code = NCONF_load( config, _PATH_OPENSSLCONFFILE, &error_line );
    if (ret_code == 0)
    {
        warn( "EAP-TLS: Error in OpenSSL config file %s at line %d", _PATH_OPENSSLCONFFILE, error_line );
        NCONF_free( config );
        config = NULL;
        ERR_clear_error();
    }

	dbglog( "Loading OpenSSL built-ins" );
    ENGINE_load_builtin_engines();
    OPENSSL_load_builtin_modules();
   
	dbglog( "Loading OpenSSL configured modules" );
    if (CONF_modules_load( config, NULL, 0 ) <= 0 )
    {
        warn( "EAP-TLS: Error loading OpenSSL modules" );
	    log_ssl_errors();
        config = NULL;
    }

    return config;
}

ENGINE *eaptls_ssl_load_engine( char *engine_name )
{
	ENGINE      *e = NULL;

	dbglog( "Enabling OpenSSL auto engines" );
	ENGINE_register_all_complete();

	dbglog( "Loading OpenSSL '%s' engine support", engine_name );
	e = ENGINE_by_id( engine_name );
    if (!e) 
	{
		dbglog( "EAP-TLS: Cannot load '%s' engine support, trying 'dynamic'", engine_name );
		e = ENGINE_by_id( "dynamic" );
		if (e)
		{
			if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine_name, 0)
   	         || !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0))
			{
				warn( "EAP-TLS: Error loading dynamic engine '%s'", engine_name );
		        log_ssl_errors();
				ENGINE_free(e);
				e = NULL;
			}
		}
		else
		{
			warn( "EAP-TLS: Cannot load dynamic engine support" );
		}
	}

    if (e)
	{
		dbglog( "Initialising engine" );
		if(!ENGINE_set_default(e, ENGINE_METHOD_ALL))
		{
			warn( "EAP-TLS: Cannot use that engine" );
			log_ssl_errors();
			ENGINE_free(e);
			e = NULL;
		}
	}

    return e;
}

/*
 * Initialize the SSL stacks and tests if certificates, key and crl
 * for client or server use can be loaded.
 */
SSL_CTX *eaptls_init_ssl(int init_server, char *cacertfile,
			char *certfile, char *peer_certfile, char *privkeyfile)
{
	char		*cert_engine_name = NULL;
	char		*cert_identifier = NULL;
	char		*pkey_engine_name = NULL;
	char		*pkey_identifier = NULL;
	SSL_CTX		*ctx;
	X509_STORE	*certstore;
	X509_LOOKUP	*lookup;
	X509		*tmp;

	/*
	 * Without these can't continue 
	 */
	if (!cacertfile[0])
    {
		error("EAP-TLS: CA certificate missing");
		return NULL;
    }

	if (!certfile[0])
    {
		error("EAP-TLS: User certificate missing");
		return NULL;
    }

	if (!privkeyfile[0])
    {
		error("EAP-TLS: User private key missing");
		return NULL;
    }

	SSL_library_init();
	SSL_load_error_strings();

	ctx = SSL_CTX_new(TLSv1_method());

	if (!ctx) {
		error("EAP-TLS: Cannot initialize SSL CTX context");
		goto fail;
	}

	/* if the certificate filename is of the form engine:id. e.g.
		pkcs11:12345
	   then we try to load and use this engine.
	   If the certificate filename starts with a / or . then we
	   ALWAYS assume it is a file and not an engine/pkcs11 identifier
	 */
	if ( index( certfile, '/' ) == NULL && index( certfile, '.') == NULL )
	{
		cert_identifier = index( certfile, ':' );

		if (cert_identifier)
		{
			cert_engine_name = certfile;
			*cert_identifier = '\0';
			cert_identifier++;

			dbglog( "Found certificate engine '%s'", cert_engine_name );
			dbglog( "Found certificate identifier '%s'", cert_identifier );
		}
	}

	/* if the privatekey filename is of the form engine:id. e.g.
		pkcs11:12345
	   then we try to load and use this engine.
	   If the privatekey filename starts with a / or . then we
	   ALWAYS assume it is a file and not an engine/pkcs11 identifier
	 */
	if ( index( privkeyfile, '/' ) == NULL && index( privkeyfile, '.') == NULL )
	{
		pkey_identifier = index( privkeyfile, ':' );

		if (pkey_identifier)
		{
			pkey_engine_name = privkeyfile;
			*pkey_identifier = '\0';
			pkey_identifier++;

			dbglog( "Found privatekey engine '%s'", pkey_engine_name );
			dbglog( "Found privatekey identifier '%s'", pkey_identifier );
		}
	}

	if (cert_identifier && pkey_identifier)
	{
		if (strlen( cert_identifier ) == 0)
		{
			if (strlen( pkey_identifier ) == 0)
				error( "EAP-TLS: both the certificate and privatekey identifiers are missing!" );
			else
			{
				dbglog( "Substituting privatekey identifier for certificate identifier" );
				cert_identifier = pkey_identifier;
			}
		}
		else
		{
			if (strlen( pkey_identifier ) == 0)
			{
				dbglog( "Substituting certificate identifier for privatekey identifier" );
				pkey_identifier = cert_identifier;
			}
		}

	}

	/* load the openssl config file only once */
	if (!ssl_config)
	{
		if (cert_engine_name || pkey_engine_name)
			ssl_config = eaptls_ssl_load_config();

		if (ssl_config && cert_engine_name)
			cert_engine = eaptls_ssl_load_engine( cert_engine_name );

		if (ssl_config && pkey_engine_name)
		{
			/* don't load the same engine twice */
			if ( strcmp( cert_engine_name, pkey_engine_name) == 0 )
				pkey_engine = cert_engine;
			else
				pkey_engine = eaptls_ssl_load_engine( pkey_engine_name );
		}
	}

    SSL_CTX_set_default_passwd_cb (ctx, password_callback);

	if (!SSL_CTX_load_verify_locations(ctx, cacertfile, NULL))
	{
		error("EAP-TLS: Cannot load or verify CA file %s", cacertfile);
		goto fail;
	}

    if (init_server)
		SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(cacertfile));

	if (cert_engine)
	{
		struct
		{
			const char *s_slot_cert_id;
			X509 *cert;
		} cert_info;

		cert_info.s_slot_cert_id = cert_identifier;
		cert_info.cert = NULL;
		
		if (!ENGINE_ctrl_cmd( cert_engine, "LOAD_CERT_CTRL", 0, &cert_info, NULL, 0 ) )
		{
			error( "EAP-TLS: Error loading certificate with id '%s' from engine", cert_identifier );
			goto fail;
		}

		if (cert_info.cert)
		{
		    dbglog( "Got the certificate, adding it to SSL context" );
			dbglog( "subject = %s", X509_NAME_oneline( X509_get_subject_name( cert_info.cert ), NULL, 0 ) );
			if (SSL_CTX_use_certificate(ctx, cert_info.cert) <= 0)
			{
				error("EAP-TLS: Cannot use PKCS11 certificate %s", cert_identifier);
				goto fail;
			}
		}
		else
		{
			warn("EAP-TLS: Cannot load PKCS11 key %s", cert_identifier);
			log_ssl_errors();
		}
	}
	else
	{
		if (!SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM))
		{
			error( "EAP-TLS: Cannot use public certificate %s", certfile );
			goto fail;
		}
	}

	if (pkey_engine)
	{
		EVP_PKEY   *pkey = NULL;
		PW_CB_DATA  cb_data;

		cb_data.password = passwd;
		cb_data.prompt_info = pkey_identifier;

		dbglog( "Loading private key '%s' from engine", pkey_identifier );
		pkey = ENGINE_load_private_key(pkey_engine, pkey_identifier, NULL, &cb_data);
		if (pkey)
		{
		    dbglog( "Got the private key, adding it to SSL context" );
			if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0)
			{
				error("EAP-TLS: Cannot use PKCS11 key %s", pkey_identifier);
				goto fail;
			}
		}
		else
		{
			warn("EAP-TLS: Cannot load PKCS11 key %s", pkey_identifier);
			log_ssl_errors();
		}
	}
	else
	{
		if (!SSL_CTX_use_PrivateKey_file(ctx, privkeyfile, SSL_FILETYPE_PEM))
		{ 
			error("EAP-TLS: Cannot use private key %s", privkeyfile);
			goto fail;
		}
	}

	if (SSL_CTX_check_private_key(ctx) != 1) {
		error("EAP-TLS: Private key %s fails security check", privkeyfile);
		goto fail;
	}

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
	SSL_CTX_set_verify_depth(ctx, 5);
	SSL_CTX_set_verify(ctx,
			   SSL_VERIFY_PEER |
			   SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			   &ssl_verify_callback);

	if (crl_dir) {
		if (!(certstore = SSL_CTX_get_cert_store(ctx))) {
			error("EAP-TLS: Failed to get certificate store");
			goto fail;
		}

		if (!(lookup =
		     X509_STORE_add_lookup(certstore, X509_LOOKUP_hash_dir()))) {
			error("EAP-TLS: Store lookup for CRL failed");

			goto fail;
		}

		X509_LOOKUP_add_dir(lookup, crl_dir, X509_FILETYPE_PEM);
		X509_STORE_set_flags(certstore, X509_V_FLAG_CRL_CHECK);
	}

	/*
	 * If a peer certificate file was specified, it must be valid, else fail 
	 */
	if (peer_certfile[0]) {
		if (!(tmp = get_X509_from_file(peer_certfile))) {
			error("EAP-TLS: Error loading client certificate from file %s",
			     peer_certfile);
			goto fail;
		}
		X509_free(tmp);
	}

	return ctx;

fail:
	log_ssl_errors();
	SSL_CTX_free(ctx);
	return NULL;
}

/*
 * Determine the maximum packet size by looking at the LCP handshake
 */

int eaptls_get_mtu(int unit)
{
	int mtu, mru;

	lcp_options *wo = &lcp_wantoptions[unit];
	lcp_options *go = &lcp_gotoptions[unit];
	lcp_options *ho = &lcp_hisoptions[unit];
	lcp_options *ao = &lcp_allowoptions[unit];

	mtu = ho->neg_mru? ho->mru: PPP_MRU;
	mru = go->neg_mru? MAX(wo->mru, go->mru): PPP_MRU;
    mtu = MIN(MIN(mtu, mru), ao->mru)- PPP_HDRLEN - 10;

	dbglog("MTU = %d", mtu);
 	return mtu;
}


/*
 * Init the ssl handshake (server mode)
 */
int eaptls_init_ssl_server(eap_state * esp)
{
	struct eaptls_session *ets;
	char servcertfile[MAXWORDLEN];
	char clicertfile[MAXWORDLEN];
	char cacertfile[MAXWORDLEN];
	char pkfile[MAXWORDLEN];
	/*
	 * Allocate new eaptls session 
	 */
	esp->es_server.ea_session = malloc(sizeof(struct eaptls_session));
	if (!esp->es_server.ea_session)
		fatal("Allocation error");
	ets = esp->es_server.ea_session;

	if (!esp->es_server.ea_peer) {
		error("EAP-TLS: Error: client name not set (BUG)");
		return 0;
	}

	strncpy(ets->peer, esp->es_server.ea_peer, MAXWORDLEN);

	dbglog( "getting eaptls secret" );
	if (!get_eaptls_secret(esp->es_unit, esp->es_server.ea_peer,
			       esp->es_server.ea_name, clicertfile,
			       servcertfile, cacertfile, pkfile, 1)) {
		error( "EAP-TLS: Cannot get secret/password for client \"%s\", server \"%s\"",
				esp->es_server.ea_peer, esp->es_server.ea_name );
		return 0;
	}

	ets->mtu = eaptls_get_mtu(esp->es_unit);

	ets->ctx = eaptls_init_ssl(1, cacertfile, servcertfile, clicertfile, pkfile);
	if (!ets->ctx)
		goto fail;

	if (!(ets->ssl = SSL_new(ets->ctx)))
		goto fail;

	/*
	 * Set auto-retry to avoid timeouts on BIO_read
	 */
	SSL_set_mode(ets->ssl, SSL_MODE_AUTO_RETRY);

	/*
	 * Initialize the BIOs we use to read/write to ssl engine 
	 */
	ets->into_ssl = BIO_new(BIO_s_mem());
	ets->from_ssl = BIO_new(BIO_s_mem());
	SSL_set_bio(ets->ssl, ets->into_ssl, ets->from_ssl);

	SSL_set_msg_callback(ets->ssl, ssl_msg_callback);
	SSL_set_msg_callback_arg(ets->ssl, ets);

	/*
	 * Attach the session struct to the connection, so we can later
	 * retrieve it when doing certificate verification
	 */
	SSL_set_ex_data(ets->ssl, 0, ets);

	SSL_set_accept_state(ets->ssl);

	ets->data = NULL;
	ets->datalen = 0;
	ets->alert_sent = 0;
	ets->alert_recv = 0;

	/*
	 * If we specified the client certificate file, store it in ets->peercertfile,
	 * so we can check it later in ssl_verify_callback()
	 */
	if (clicertfile[0])
		strncpy(&ets->peercertfile[0], clicertfile, MAXWORDLEN);
	else
		ets->peercertfile[0] = 0;

	return 1;

fail:
	SSL_CTX_free(ets->ctx);
	return 0;
}

/*
 * Init the ssl handshake (client mode)
 */
int eaptls_init_ssl_client(eap_state * esp)
{
	struct eaptls_session *ets;
	char servcertfile[MAXWORDLEN];
	char clicertfile[MAXWORDLEN];
	char cacertfile[MAXWORDLEN];
	char pkfile[MAXWORDLEN];

	/*
	 * Allocate new eaptls session 
	 */
	esp->es_client.ea_session = malloc(sizeof(struct eaptls_session));
	if (!esp->es_client.ea_session)
		fatal("Allocation error");
	ets = esp->es_client.ea_session;

	/*
	 * If available, copy server name in ets; it will be used in cert
	 * verify 
	 */
	if (esp->es_client.ea_peer)
		strncpy(ets->peer, esp->es_client.ea_peer, MAXWORDLEN);
	else
		ets->peer[0] = 0;
	
	ets->mtu = eaptls_get_mtu(esp->es_unit);

	dbglog( "calling get_eaptls_secret" );
	if (!get_eaptls_secret(esp->es_unit, esp->es_client.ea_name,
			       esp->es_client.ea_peer, clicertfile,
			       servcertfile, cacertfile, pkfile, 0)) {
		error( "EAP-TLS: Cannot get secret/password for client \"%s\", server \"%s\"",
				esp->es_client.ea_name, esp->es_client.ea_peer );
		return 0;
	}

	dbglog( "calling eaptls_init_ssl" );
	ets->ctx = eaptls_init_ssl(0, cacertfile, clicertfile, servcertfile, pkfile);
	if (!ets->ctx)
		goto fail;

	ets->ssl = SSL_new(ets->ctx);

	if (!ets->ssl)
		goto fail;

	/*
	 * Initialize the BIOs we use to read/write to ssl engine 
	 */
	dbglog( "Initializing SSL BIOs" );
	ets->into_ssl = BIO_new(BIO_s_mem());
	ets->from_ssl = BIO_new(BIO_s_mem());
	SSL_set_bio(ets->ssl, ets->into_ssl, ets->from_ssl);

	SSL_set_msg_callback(ets->ssl, ssl_msg_callback);
	SSL_set_msg_callback_arg(ets->ssl, ets);

	/*
	 * Attach the session struct to the connection, so we can later
	 * retrieve it when doing certificate verification
	 */
	SSL_set_ex_data(ets->ssl, 0, ets);

	SSL_set_connect_state(ets->ssl);

	ets->data = NULL;
	ets->datalen = 0;
	ets->alert_sent = 0;
	ets->alert_recv = 0;

	/*
	 * If we specified the server certificate file, store it in
	 * ets->peercertfile, so we can check it later in
	 * ssl_verify_callback() 
	 */
	if (servcertfile[0])
		strncpy(ets->peercertfile, servcertfile, MAXWORDLEN);
	else
		ets->peercertfile[0] = 0;

	return 1;

fail:
	dbglog( "eaptls_init_ssl_client: fail" );
	SSL_CTX_free(ets->ctx);
	return 0;

}

void eaptls_free_session(struct eaptls_session *ets)
{
	if (ets->ssl)
		SSL_free(ets->ssl);

	if (ets->ctx)
		SSL_CTX_free(ets->ctx);

	free(ets);
}

/*
 * Handle a received packet, reassembling fragmented messages and
 * passing them to the ssl engine
 */
int eaptls_receive(struct eaptls_session *ets, u_char * inp, int len)
{
	u_char flags;
	u_int tlslen;
	u_char dummy[65536];

	GETCHAR(flags, inp);
	len--;

    if (flags & EAP_TLS_FLAGS_LI && !ets->data) {
 
		/*
		 * This is the first packet of a message
		*/
 
		GETLONG(tlslen, inp);
		len -= 4;

		if (tlslen > EAP_TLS_MAX_LEN) {
			error("Error: tls message length > %d, truncated",
				EAP_TLS_MAX_LEN);
			tlslen = EAP_TLS_MAX_LEN;
		}

		/*
		 * Allocate memory for the whole message
		*/
		ets->data = malloc(tlslen);
		if (!ets->data)
			fatal("EAP TLS: allocation error\n");

		ets->datalen = 0;
		ets->tlslen = tlslen;

	}
	else if (flags & EAP_TLS_FLAGS_LI && ets->data) {
		/*
		 * Non first with LI (strange...)
		*/
 
		GETLONG(tlslen, inp);
		len -= 4;
 
	}
	else if (!ets->data) {
		/*
		 * A non fragmented message without LI flag
		*/
 
		ets->data = malloc(len);
		if (!ets->data)
			fatal("EAP TLS: allocation error\n");
 
		ets->datalen = 0;
		ets->tlslen = len;
	}

	if (flags & EAP_TLS_FLAGS_MF)
		ets->frag = 1;
	else
		ets->frag = 0;

	if (len + ets->datalen > ets->tlslen) {
		warn("EAP TLS: received data > TLS message length");
		return 1;
	}

	BCOPY(inp, ets->data + ets->datalen, len);
	ets->datalen += len;

	if (!ets->frag) {

		/*
		 * If we have the whole message, pass it to ssl 
		 */

		if (ets->datalen != ets->tlslen) {
			warn("EAP TLS: received data != TLS message length");
			return 1;
		}

		if (BIO_write(ets->into_ssl, ets->data, ets->datalen) == -1)
			log_ssl_errors();

		SSL_read(ets->ssl, dummy, 65536);

		free(ets->data);
		ets->data = NULL;
		ets->datalen = 0;
	}

	return 0;
}

/*
 * Return an eap-tls packet in outp.
 * A TLS message read from the ssl engine is buffered in ets->data.
 * At each call we control if there is buffered data and send a 
 * packet of mtu bytes.
 */
int eaptls_send(struct eaptls_session *ets, u_char ** outp)
{
	bool first = 0;
	int size;
	u_char fromtls[65536];
	int res;
	u_char *start;

	start = *outp;

	if (!ets->data) {

		if(!ets->alert_sent)
			SSL_read(ets->ssl, fromtls, 65536);

		/*
		 * Read from ssl 
		 */
		if ((res = BIO_read(ets->from_ssl, fromtls, 65536)) == -1)
			fatal("No data from BIO_read");

		ets->datalen = res;

		ets->data = malloc(ets->datalen);
		BCOPY(fromtls, ets->data, ets->datalen);

		ets->offset = 0;
		first = 1;

	}

	size = ets->datalen - ets->offset;
    
	if (size > ets->mtu) {
		size = ets->mtu;
		ets->frag = 1;
	} else
		ets->frag = 0;

	PUTCHAR(EAPT_TLS, *outp);

	/*
	 * Set right flags and length if necessary 
	 */
	if (ets->frag && first) {
		PUTCHAR(EAP_TLS_FLAGS_LI | EAP_TLS_FLAGS_MF, *outp);
		PUTLONG(ets->datalen, *outp);
	} else if (ets->frag) {
		PUTCHAR(EAP_TLS_FLAGS_MF, *outp);
	} else
		PUTCHAR(0, *outp);

	/*
	 * Copy the data in outp 
	 */
	BCOPY(ets->data + ets->offset, *outp, size);
	INCPTR(size, *outp);

	/*
	 * Copy the packet in retransmission buffer 
	 */
	BCOPY(start, &ets->rtx[0], *outp - start);
	ets->rtx_len = *outp - start;

	ets->offset += size;

	if (ets->offset >= ets->datalen) {

		/*
		 * The whole message has been sent 
		 */

		free(ets->data);
		ets->data = NULL;
		ets->datalen = 0;
		ets->offset = 0;
	}

	return 0;
}

/*
 * Get the sent packet from the retransmission buffer
 */
void eaptls_retransmit(struct eaptls_session *ets, u_char ** outp)
{
	BCOPY(ets->rtx, *outp, ets->rtx_len);
	INCPTR(ets->rtx_len, *outp);
}

/*
 * Verify a certificate.
 * Most of the work (signatures and issuer attributes checking)
 * is done by ssl; we check the CN in the peer certificate 
 * against the peer name.
 */
int ssl_verify_callback(int preverify_ok, X509_STORE_CTX * ctx)
{
	char subject[256];
	char cn_str[256];
	X509 *peer_cert;
	int err, depth;
	int ok = preverify_ok;
	SSL *ssl;
	struct eaptls_session *ets;

	peer_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);

	dbglog("certificate verify depth: %d", depth);

    if (auth_required && !ok) {
		X509_NAME_oneline(X509_get_subject_name(peer_cert),
				  subject, 256);

		X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert),
					  NID_commonName, cn_str, 256);

		dbglog("Certificate verification error:\n depth: %d CN: %s"
		       "\n err: %d (%s)\n", depth, cn_str, err,
		       X509_verify_cert_error_string(err));

		return 0;
	}

	ssl = X509_STORE_CTX_get_ex_data(ctx,
				       SSL_get_ex_data_X509_STORE_CTX_idx());

	ets = (struct eaptls_session *)SSL_get_ex_data(ssl, 0);

	if (ets == NULL) {
		error("Error: SSL_get_ex_data returned NULL");
		return 0;
	}

	log_ssl_errors();

	if (!depth) {		/* This is the peer certificate */

		X509_NAME_oneline(X509_get_subject_name(peer_cert),
				  subject, 256);

		X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert),
					  NID_commonName, cn_str, 256);

		/*
		 * If acting as client and the name of the server wasn't specified
		 * explicitely, we can't verify the server authenticity 
		 */
		if (!ets->peer[0]) {
			warn("Peer name not specified: no check");
			return 1;
		}

		/*
		 * Check the CN 
		 */
		if (strcmp(cn_str, ets->peer)) {
			error
			    ("Certificate verification error: CN (%s) != peer_name (%s)",
			     cn_str, ets->peer);
			return 0;
		}

		warn("Certificate CN: %s , peer name %s", cn_str, ets->peer);

		/*
		 * If a peer certificate file was specified, here we check it 
		 */
		if (ets->peercertfile[0]) {
			if (ssl_cmp_certs(&ets->peercertfile[0], peer_cert)
			    != 0) {
				error
				    ("Peer certificate doesn't match stored certificate");
				return 0;
			}
		}
	}

	return 1;
}

/*
 * Compare a certificate with the one stored in a file
 */
int ssl_cmp_certs(char *filename, X509 * a)
{
	X509 *b;
	int ret;

	if (!(b = get_X509_from_file(filename)))
		return 1;

	ret = X509_cmp(a, b);
	X509_free(b);

	return ret;

}

X509 *get_X509_from_file(char *filename)
{
	FILE *fp;
	X509 *ret;

	if (!(fp = fopen(filename, "r")))
		return NULL;

	ret = PEM_read_X509(fp, NULL, NULL, NULL);

	fclose(fp);

	return ret;
}

/*
 * Every sent & received message this callback function is invoked,
 * so we know when alert messages have arrived or are sent and
 * we can print debug information about TLS handshake.
 */
void
ssl_msg_callback(int write_p, int version, int content_type,
		 const void *buf, size_t len, SSL * ssl, void *arg)
{
	char string[256];
	struct eaptls_session *ets = (struct eaptls_session *)arg;
	unsigned char code;

	if(write_p)
		strcpy(string, " -> ");
	else
		strcpy(string, " <- ");

	
	switch(content_type) {

	case SSL3_RT_ALERT:	
		strcat(string, "Alert: ");	
		code = ((const unsigned char *)buf)[1];

		if (write_p) {
			ets->alert_sent = 1;
			ets->alert_sent_desc = code;
		} else {
			ets->alert_recv = 1;
			ets->alert_recv_desc = code;
		}

		strcat(string, SSL_alert_desc_string_long(code));
		break;

	case SSL3_RT_CHANGE_CIPHER_SPEC:
		strcat(string, "ChangeCipherSpec");
		break;

	case SSL3_RT_HANDSHAKE:

		strcat(string, "Handshake: ");
		code = ((const unsigned char *)buf)[0];

		switch(code) {
			case SSL3_MT_HELLO_REQUEST:
				strcat(string,"Hello Request");
				break;
			case SSL3_MT_CLIENT_HELLO:
				strcat(string,"Client Hello");
				break;
			case SSL3_MT_SERVER_HELLO:
				strcat(string,"Server Hello");
				break;
			case SSL3_MT_CERTIFICATE:
				strcat(string,"Certificate");
				break;
			case SSL3_MT_SERVER_KEY_EXCHANGE:
				strcat(string,"Server Key Exchange");
				break;
			case SSL3_MT_CERTIFICATE_REQUEST:
				strcat(string,"Certificate Request");
				break;
			case SSL3_MT_SERVER_DONE:
				strcat(string,"Server Hello Done");
								break;
			case SSL3_MT_CERTIFICATE_VERIFY:
				strcat(string,"Certificate Verify");
				break;
			case SSL3_MT_CLIENT_KEY_EXCHANGE:
				strcat(string,"Client Key Exchange");
				break;
			case SSL3_MT_FINISHED:
				strcat(string,"Finished");
				break;

			default:
				sprintf( string, "Handshake: Unknown SSL3 code received: %d", code );
		}
		break;

	default:
		sprintf( string, "SSL message contains unknown content type: %d", content_type );
		
	}

	/* Alert messages must always be displayed */
	if(content_type == SSL3_RT_ALERT)
		error("%s", string);
	else
		dbglog("%s", string);
}

