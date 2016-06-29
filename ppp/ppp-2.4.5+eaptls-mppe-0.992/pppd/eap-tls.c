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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <cyassl/ssl.h>
#include <cyassl/ctaocrypt/logging.h>
#ifdef MPPE
#include <cyassl/ctaocrypt/hmac.h>
#endif

#include "pppd.h"
#include "eap.h"
#include "eap-tls.h"
#include "fsm.h"
#include "lcp.h"
#include "pathnames.h"

int cyassl_recv_callback(char *buf, int sz, void *ctx);
int cyassl_send_callback(char *buf, int sz, void *ctx);
void cyassl_logging_callback(const int logLevel, const char *const logMessage);
int cyassl_verify_callback(int preverify, CYASSL_X509_STORE_CTX *ctx);

extern char *dh_params;
extern char *suite_list;

#ifdef MPPE

/*
 * TLS PRF from RFC 2246
 */
static void P_hash(const int hmac_type,
		   const unsigned char *secret, unsigned int secret_len,
		   const unsigned char *seed,   unsigned int seed_len,
		   unsigned char *out, unsigned int out_len)
{
	Hmac hmac_a, hmac_out;
	unsigned char a[SHA_DIGEST_SIZE];
	unsigned int size;

	HmacSetKey(&hmac_a, hmac_type, secret, secret_len);
	HmacSetKey(&hmac_out, hmac_type, secret, secret_len);

	size = (hmac_type == MD5) ? MD5_DIGEST_SIZE : SHA_DIGEST_SIZE;

	/* Calculate A(1) */
	HmacUpdate(&hmac_a, seed, seed_len);
	HmacFinal(&hmac_a, a);

	while (1) {
		/* Calculate next part of output */
		HmacUpdate(&hmac_out, a, size);
		HmacUpdate(&hmac_out, seed, seed_len);

		/* Check if last part */
		if (out_len < size) {
			HmacFinal(&hmac_out, a);
			memcpy(out, a, out_len);
			break;
		}

		/* Place digest in output buffer */
		HmacFinal(&hmac_out, out);
		out += size;
		out_len -= size;

		/* Calculate next A(i) */
		HmacUpdate(&hmac_a, a, size);
		HmacFinal(&hmac_a, a);
	}

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

	P_hash(MD5, s1, len, seed, seed_len, out, out_len);
	P_hash(SHA, s2, len, seed, seed_len, buf, out_len);

	for (i=0; i < out_len; i++) {
		out[i] ^= buf[i];
	}
}

#define EAPTLS_MPPE_KEY_LEN	32
#define RAN_LEN			32
#define SECRET_LEN		48

/*
 *  Generate keys according to RFC 2716 and add to reply
 */
void eaptls_gen_mppe_keys(struct eaptls_session *ets, const char *prf_label,
				int client)
{
	unsigned char out[4*EAPTLS_MPPE_KEY_LEN], buf[4*EAPTLS_MPPE_KEY_LEN];
	unsigned char seed[64 + 2*RAN_LEN];
	unsigned char *p = seed;
	CYASSL *s = ets->ssl;
	size_t prf_size;
	unsigned char *masterSecret, *clientRandom, *serverRandom;
	unsigned int msLen, crLen, srLen;

	prf_size = strlen(prf_label);

	memcpy(p, prf_label, prf_size);
	p += prf_size;

	CyaSSL_get_keys(s,
			&masterSecret, &msLen,
			&serverRandom, &srLen,
			&clientRandom, &crLen);

	memcpy(p, clientRandom, RAN_LEN);
	p += RAN_LEN;
	prf_size += RAN_LEN;

	memcpy(p, serverRandom, RAN_LEN);
	prf_size += RAN_LEN;

	PRF(masterSecret, SECRET_LEN,
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

void log_ssl_error(CYASSL *ssl)
{
	int err = 0;

	if (ssl != NULL) err = CyaSSL_get_error(ssl, 0);
	
	if (err != 0)
	{
		char err_str[80];
		CyaSSL_ERR_error_string_n(err, err_str, 80);
		dbglog("EAP-TLS CyaSSL error:");
		dbglog(err_str);
	}
}


int password_callback(char *buf, int size, int rwflag, void *u)
{
	if (buf)
	{
		strncpy(buf, passwd, size);
		return strlen(buf);
	}
	return 0;
}


/*
 * Initialize the SSL stacks and tests if certificates, key and crl
 * for client or server use can be loaded.
 */
CYASSL_CTX *eaptls_init_ssl(int init_server, char *cacertfile,
			char *certfile, char *peer_certfile, char *privkeyfile)
{
	CYASSL_CTX		*ctx;
	CYASSL_METHOD   *method;
	/* peer_certfile isn't used. The old code would load the certificate
	   and make sure it could process it, then would let it go to be reloaded
	   later. */

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

	CyaSSL_Init();
    
	if (debug != 0)
	{
		CyaSSL_SetLoggingCb(cyassl_logging_callback);
		CyaSSL_Debugging_ON();
	}
	
	method = init_server ?
		CyaSSLv23_server_method() : CyaSSLv23_client_method();
	ctx = CyaSSL_CTX_new(method);

	if (!ctx) {
		error("EAP-TLS: Cannot initialize SSL CTX context");
		return NULL;
	}

	CyaSSL_CTX_set_default_passwd_cb(ctx, password_callback);

	{
		struct stat st = {0};
		char *pFile = NULL;
		char *pDir = NULL;

		stat(cacertfile, &st);
		if (!S_ISREG(st.st_mode) && S_ISDIR(st.st_mode))
		{
			pDir = cacertfile;
		}
		else
		{
			pFile = cacertfile;
		}

		dbglog( "cacertfile: %s", cacertfile );
		dbglog( "cacertfilename: %s", pFile ? pFile : "<none>" );
		dbglog( "cacertpath: %s", pDir ? pDir : "<none>" );

		if (!CyaSSL_CTX_load_verify_locations(ctx, pFile, pDir))
		{
			error("EAP-TLS: Cannot load or verify CA file %s", cacertfile);
			goto fail;
		}
	}

	if (!CyaSSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM))
	{
		error( "EAP-TLS: Cannot use public certificate %s", certfile );
		goto fail;
	}

	if (!CyaSSL_CTX_use_PrivateKey_file(ctx, privkeyfile, SSL_FILETYPE_PEM))
	{ 
		error("EAP-TLS: Cannot use private key %s", privkeyfile);
		goto fail;
	}

	if (CyaSSL_CTX_check_private_key(ctx) != 1) {
		error("EAP-TLS: Private key %s fails security check", privkeyfile);
		goto fail;
	}

	CyaSSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
	CyaSSL_CTX_set_verify(ctx,
		SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		&cyassl_verify_callback);
	
	/*
	 * Only try to load the dh_params file if this is a sever instance,
	 * and there is a file name.
	 */	
	if (init_server && dh_params && dh_params[0])
	{
		dbglog("EAP-TLS: DH params = %s", dh_params);
		if (CyaSSL_CTX_SetTmpDH_file(ctx, dh_params, SSL_FILETYPE_PEM) < 0)
		{
			error("EAP-TLS: Unable to load the DH params file %s", dh_params);
			goto fail;
		}
	}

	if (suite_list && suite_list[0])
	{
		dbglog( "EAP-TLS loading cipher suite list: %s", suite_list);
		if (!CyaSSL_CTX_set_cipher_list(ctx, suite_list))
		{
			error("EAP-TLS: Error setting cipher suites");
			goto fail;
		}
	}

	return ctx;

fail:
	CyaSSL_CTX_free(ctx);
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
		return 0;

	ets->ssl = CyaSSL_new(ets->ctx);
	if (!ets->ssl)
		goto fail;

	/* The SSL will check the domain name for us during connection verification. */
	if (ets->peer[0])
		CyaSSL_check_domain_name(ets->ssl, ets->peer);

	CyaSSL_SetIORecv(ets->ctx, cyassl_recv_callback);
	CyaSSL_SetIOReadCtx(ets->ssl, ets);
	CyaSSL_SetIOSend(ets->ctx, cyassl_send_callback);
	CyaSSL_SetIOWriteCtx(ets->ssl, ets);

	/*
	 * Attach the session struct to the connection, so we can later
	 * retrieve it when doing certificate verification
	 */
	CyaSSL_set_ex_data(ets->ssl, 0, ets);
	
	CyaSSL_set_accept_state(ets->ssl);

	ets->data = NULL;
	ets->datalen = 0;
	ets->alert_sent = 0;
	ets->alert_recv = 0;

	/*
	 * If we specified the client certificate file, store it in ets->peercertfile.
	 */
	if (clicertfile[0])
		strncpy(&ets->peercertfile[0], clicertfile, MAXWORDLEN);
	else
		ets->peercertfile[0] = 0;

	return 1;

fail:
	CyaSSL_CTX_free(ets->ctx);
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
		return 0;

	ets->ssl = CyaSSL_new(ets->ctx);
	if (!ets->ssl)
		goto fail;

	/* The SSL will check the domain name for us during connection verification. */
	if (ets->peer[0])
		CyaSSL_check_domain_name(ets->ssl, ets->peer);

	CyaSSL_SetIORecv(ets->ctx, cyassl_recv_callback);
	CyaSSL_SetIOReadCtx(ets->ssl, ets);
	CyaSSL_SetIOSend(ets->ctx, cyassl_send_callback);
	CyaSSL_SetIOWriteCtx(ets->ssl, ets);

	/*
	 * Attach the session struct to the connection, so we can later
	 * retrieve it when doing certificate verification
	 */
	CyaSSL_set_ex_data(ets->ssl, 0, ets);
	
	CyaSSL_set_connect_state(ets->ssl);

	ets->data = NULL;
	ets->datalen = 0;
	ets->alert_sent = 0;
	ets->alert_recv = 0;

	/*
	 * If we specified the server certificate file, store it in ets->peercertfile.
	 */
	if (servcertfile[0])
		strncpy(ets->peercertfile, servcertfile, MAXWORDLEN);
	else
		ets->peercertfile[0] = 0;

	return 1;

fail:
	dbglog( "eaptls_init_ssl_client: fail" );
	CyaSSL_CTX_free(ets->ctx);
	return 0;

}

void eaptls_free_session(struct eaptls_session *ets)
{
	if (ets->ssl)
		CyaSSL_free(ets->ssl);

	if (ets->ctx)
		CyaSSL_CTX_free(ets->ctx);

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
	ets->rwstate = EAP_TLS_READ_STATE;

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
		ets->rwstate = EAP_TLS_NONE_STATE;
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
			ets->rwstate = EAP_TLS_NONE_STATE;
			return 1;
		}
		ets->dataused = 0;
		CyaSSL_negotiate(ets->ssl);

		free(ets->data);
		ets->data = NULL;
		ets->datalen = 0;
		ets->dataused = 0;

	}

	ets->rwstate = EAP_TLS_NONE_STATE;
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
	u_char *start;
	start = *outp;
	ets->rwstate = EAP_TLS_WRITE_STATE;

	if (!ets->data) {

		if(!ets->alert_sent) {
			CyaSSL_negotiate(ets->ssl);
		}
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

	ets->rwstate = EAP_TLS_NONE_STATE;
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
 * Callback from cyassl to actually process the receive
 * buffer. Will copy data from the buffer provided by
 * EAP-TLS and write it into the the buffer from cyassl.
 */
int cyassl_recv_callback(char *buf, int sz, void *ctx)
{
	struct eaptls_session *ets = (struct eaptls_session *)ctx;
	int recvd = 0;

	if (ets->rwstate == EAP_TLS_READ_STATE && ets->data)
	{
		int available = ets->datalen - ets->dataused;
		if (sz <= available)
		{
			recvd = sz;
		}
		else
		{
			recvd = available;
		}
		BCOPY(ets->data + ets->dataused, buf, recvd);
		ets->dataused += recvd;
	}
	else
		recvd = -2;

	return recvd;
}

/*
 * Callback from cyassl to actually process the send
 * buffer. Will read data provided by CyaSSL and copy
 * it to the buffer provided by EAP-TLS. If the buffer
 * from EAP-TLS isn't big enough, it will be resized.
 */
int cyassl_send_callback(char *buf, int sz, void *ctx)
{
	struct eaptls_session *ets = (struct eaptls_session *)ctx;
	int sent = 0;
	
	if (ets->rwstate == EAP_TLS_WRITE_STATE)
	{
		if (!ets->data)
		{
            ets->dataused = 0;
			ets->datalen = sz;
			ets->data = malloc(sz);
		}
		else
		{
			ets->datalen += sz;
			ets->data = realloc(ets->data, ets->datalen);
		}
		sent = sz;
		BCOPY(buf, ets->data + ets->dataused, sz);
		ets->dataused = ets->datalen;
	}
	else
		sent = -2;

	return sent;
}

/*
 * Callback from cyassl to log its debugging messages.
 * The callback has a different signature than dbglog(),
 * so this calls dbglog().
 */
void cyassl_logging_callback(const int logLevel, const char *const logMessage)
{
	dbglog("%s", logMessage);
}

/*
 * Callback from cyassl to compare the received peer certificate to a
 * local copy stored in the specified file.
 */
int cyassl_verify_callback(int preverify, CYASSL_X509_STORE_CTX *ctx)
{
	if (preverify)
	{
		CYASSL *ssl;
		struct eaptls_session *ets;
		
		ssl = (CYASSL *)CyaSSL_X509_STORE_CTX_get_ex_data(ctx,
								CyaSSL_get_ex_data_X509_STORE_CTX_idx());
		ets = (struct eaptls_session *)CyaSSL_get_ex_data(ssl, 0);

		if (ets->peercertfile[0])
		{
			if (CyaSSL_cmp_peer_cert_to_file(ssl, ets->peercertfile) != 0)
			{
				error("Peer certificate doesn't match stored certificate");
				preverify = 0;
			}
		}
	}

	return preverify;
}


