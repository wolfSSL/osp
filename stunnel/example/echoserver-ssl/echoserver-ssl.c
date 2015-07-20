/* echoserver.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as wolfSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/ssl.h>
#include <../include/test.h>

#include "../include/echoserver.h"

#define SVR_COMMAND_SIZE 256

THREAD_RETURN WOLFSSL_THREAD echoserver_test(void* args)
{
    SOCKET_T       sockfd = 0;
    WOLFSSL_METHOD* method = 0;
    WOLFSSL_CTX*    ctx    = 0;

    int    doDTLS = 0;
    int    doPSK = 0;
    int    shutDown = 0;
    int    useAnyAddr = 0;
    word16 port = wolfSSLPort;
    int    argc = ((func_args*)args)->argc;
    char** argv = ((func_args*)args)->argv;

    (void)argc;
    (void)argv;

    ((func_args*)args)->return_code = -1; /* error state */

    tcp_listen(&sockfd, &port, useAnyAddr, doDTLS);



    method = wolfSSLv23_server_method();
    ctx    = wolfSSL_CTX_new(method);
    /* wolfSSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF); */

        if (wolfSSL_CTX_use_certificate_file(ctx, svrCert, SSL_FILETYPE_PEM)
                != SSL_SUCCESS)
            err_sys("can't load server cert file, "
                    "Please run from examples dir");

        if (wolfSSL_CTX_use_PrivateKey_file(ctx, svrKey, SSL_FILETYPE_PEM)
                != SSL_SUCCESS)
            err_sys("can't load server key file, "
                    "Please run from examples dir");

    while (!shutDown) {
        WOLFSSL* ssl = 0;
        char    command[SVR_COMMAND_SIZE+1];
        int     echoSz = 0;
        int     clientfd;
        int     firstRead = 1;
        int     gotFirstG = 0;


        SOCKADDR_IN_T client;
        socklen_t     client_len = sizeof(client);
        clientfd = accept(sockfd, (struct sockaddr*)&client,
                         (ACCEPT_THIRD_T)&client_len);

        if (clientfd == -1) err_sys("tcp accept failed");

        ssl = wolfSSL_new(ctx);
        if (ssl == NULL) err_sys("SSL_new failed");
        wolfSSL_set_fd(ssl, clientfd);
        #if !defined(NO_FILESYSTEM) && !defined(NO_DH) && !defined(NO_ASN)
            wolfSSL_SetTmpDH_file(ssl, dhParam, SSL_FILETYPE_PEM);
        #elif !defined(NO_DH)
            SetDH(ssl);  /* will repick suites with DHE, higher than PSK */
        #endif
        if (wolfSSL_accept(ssl) != SSL_SUCCESS) {
            printf("SSL_accept failed\n");
            wolfSSL_free(ssl);
            CloseSocket(clientfd);
            continue;
        }
#if defined(PEER_INFO)
        showPeer(ssl);
#endif

        while ( (echoSz = wolfSSL_read(ssl, command, sizeof(command)-1)) > 0) {

            if (firstRead == 1) {
                firstRead = 0;  /* browser may send 1 byte 'G' to start */
                if (echoSz == 1 && command[0] == 'G') {
                    gotFirstG = 1;
                    continue;
                }
            }
            else if (gotFirstG == 1 && strncmp(command, "ET /", 4) == 0) {
                strncpy(command, "GET", 4);
                /* fall through to normal GET */
            }
           
            if ( strncmp(command, "quit", 4) == 0) {
                printf("client sent quit command: shutting down!\n");
                shutDown = 1;
                break;
            }
            if ( strncmp(command, "break", 5) == 0) {
                printf("client sent break command: closing session!\n");
                break;
            }

            if ( strncmp(command, "GET", 3) == 0) {
                char type[]   = "HTTP/1.0 200 ok\r\nContent-type:"
                                " text/html\r\n\r\n";
                char header[] = "<html><body BGCOLOR=\"#ffffff\">\n<pre>\n";
                char body[]   = "greetings from wolfSSL\n";
                char footer[] = "</body></html>\r\n\r\n";
            
                strncpy(command, type, sizeof(type));
                echoSz = sizeof(type) - 1;

                strncpy(&command[echoSz], header, sizeof(header));
                echoSz += (int)sizeof(header) - 1;
                strncpy(&command[echoSz], body, sizeof(body));
                echoSz += (int)sizeof(body) - 1;
                strncpy(&command[echoSz], footer, sizeof(footer));
                echoSz += (int)sizeof(footer);

                if (wolfSSL_write(ssl, command, echoSz) != echoSz)
                    err_sys("SSL_write failed");
                break;
            }
            command[echoSz] = 0;


            if (wolfSSL_write(ssl, command, echoSz) != echoSz)
                err_sys("SSL_write failed");
        }
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        CloseSocket(clientfd);
    }

    CloseSocket(sockfd);
    wolfSSL_CTX_free(ctx);


    ((func_args*)args)->return_code = 0;
    return 0;
}



    int main(int argc, char** argv)
    {
        func_args args;

        StartTCP();

        args.argc = argc;
        args.argv = argv;

        wolfSSL_Init();
#if defined(DEBUG_WOLFSSL)
        wolfSSL_Debugging_ON();
#endif
        if (CurrentDir("echoserver"))
            ChangeDirBack(2);
        else if (CurrentDir("Debug") || CurrentDir("Release"))
            ChangeDirBack(3);
        echoserver_test(&args);
        wolfSSL_Cleanup();

        return args.return_code;
    }



