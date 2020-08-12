/* server-tls-threaded.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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

/* the usual suspects */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

/* threads */
#include <pthread.h>

//ncurses
#include "minitalk.c"

#define DEFAULT_PORT 11111


#define CERT_FILE "./certs/server-cert.pem"
#define KEY_FILE "./certs/server-key.pem"

/* Thread argument package */
/*struct targ_pkg
{
    int open;
    pthread_t tid;
    int num;
    int connd;
    WOLFSSL_CTX *ctx;
    int *shutdown;
};*/

//Global Variables
WOLFSSL_CTX *ctx;
WOLFSSL *ssl;
size_t len;
char buff[256];
char buffReader[256];
char username[256];
int sockfd;
int connd;
struct sockaddr_in servAddr;
struct sockaddr_in clientAddr;
socklen_t size = sizeof(clientAddr);
//struct targ_pkg *pkg;
extern char Rbuffer[256];

void *readBuffer(void *args)
{
    int ret;
    while (1)
    {
        /* Read the client data into our buff array */
        XMEMSET(buffReader, 0, sizeof(buffReader));
        /*do
        {*/
        ret = wolfSSL_read(ssl, buffReader, sizeof(buffReader) - 1);
        /* TODO: Currently this thread can get stuck infinitely if client
         *       disconnects, add timer to abort on a timeout eventually,
         *       just an example for now so allow for possible stuck condition
         */
        //} while (wolfSSL_want_read(ssl));

        if (ret > 0)
        {
            printText(buffReader, username);
        }
        else
        {
            /*printf("wolfSSL_read encountered an error with code %d and msg %s\n",
                   ret, wolfSSL_ERR_error_string(ret, buffReader));*/
            printText("ERROR READ!!", "System");
            pthread_exit(NULL); /* End theread execution                */
        }

        /* Check for server shutdown command */
        if (XSTRNCMP(buffReader, "shutdown", 8) == 0)
        {
            printf("Shutdown command issued!\n");
        }
    }
}

void *writeBuffer(void *args)
{
    int ret;
    while (1)
    {
        read_in();
        /*if (fgets(buff, sizeof(buff), stdin) == NULL)
        {
            fprintf(stderr, "ERROR: failed to get message for server\n");
            return NULL;
        }*/
        /* Write our reply into buff */
        //XMEMSET(buff, 0, sizeof(buff));
        len = XSTRLEN(Rbuffer);
        //XMEMCPY(buff, reply, len);

        /* Reply back to the client */
        do
        {
            ret = wolfSSL_write(ssl, Rbuffer, len);
            /* TODO: Currently this thread can get stuck infinitely if client
         *       disconnects, add timer to abort on a timeout eventually,
         *       just an example for now so allow for possible stuck condition
         */
            printText(Rbuffer, "Server");
        } while (wolfSSL_want_write(ssl));

        if (ret != len)
        {
            /*char *err="";
            err = sprintf("wolfSSL_write encountered an error with code %d and msg %s\n",
                   ret, wolfSSL_ERR_error_string(ret, Rbuffer));*/
            printText("ERROR!!", "System");
            /*printf("wolfSSL_write encountered an error with code %d and msg %s\n",
                   ret, wolfSSL_ERR_error_string(ret, Rbuffer));*/
        }
    }
}

void *ClientHandler(void *args)
{
    int ret;
    //printf("Client %d connected successfully\n", pkg->num);

    /*********************** USERNAME */
    /* Read the client username into our buff array */
    XMEMSET(buff, 0, sizeof(buff));
    ret = wolfSSL_read(ssl, buff, sizeof(buff) - 1);
    ncurses_start();
    clearWin();
    if (ret > 0)
    {
        /* Print to stdout any data the client sends */
        strcpy(username, buff);
        char text[256];
        sprintf(text, "Client %s connected successfully", username);
        printText(text, "System");
        printText("***************************\n", "System");
        fflush(stdout);
    }
    else
    {
        /*printf("wolfSSL_read encountered an error with code %d and msg %s\n",
               ret, wolfSSL_ERR_error_string(ret, buff));*/
        printText("ERROR!!", "System");
        wolfSSL_free(ssl);  /* Free the wolfSSL object              */
        close(sockfd);      /* Close the connection to the server   */
        pthread_exit(NULL); /* End theread execution                */
    }
    /****************************    */
    XMEMSET(buff, 0, sizeof(buff));

    //create Thread Reader
    pthread_t Treader;
    if (pthread_create(&Treader, NULL, readBuffer, NULL))
    {
        fprintf(stderr, "Error creating thread\n");
        fflush(stdout);
        return NULL;
    }

    //create Thread Writer
    pthread_t Twriter;
    if (pthread_create(&Twriter, NULL, writeBuffer, NULL))
    {
        fprintf(stderr, "Error creating thread\n");
        fflush(stdout);
        return NULL;
    }
    pthread_join(Treader, NULL);
    pthread_cancel(Twriter);
    //pthread_join(Twriter, NULL);
    ncurses_end();
    /* Cleanup after this connection */
    wolfSSL_free(ssl);  /* Free the wolfSSL object              */
    close(connd);      /* Close the connection to the client   */
    pthread_exit(NULL); /* End theread execution                */
}

int main()
{
    int shutdown = 0;
    int ret;

    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        return -1;
    }

    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL)
    {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        return -1;
    }

    /* Load server certificates into WOLFSSL_CTX */
    if (wolfSSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) != SSL_SUCCESS)
    {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                CERT_FILE);
        return -1;
    }

    /* Load server key into WOLFSSL_CTX */
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) != SSL_SUCCESS)
    {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                KEY_FILE);
        return -1;
    }

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family = AF_INET;           /* using IPv4      */
    servAddr.sin_port = htons(DEFAULT_PORT); /* on DEFAULT_PORT */
    servAddr.sin_addr.s_addr = INADDR_ANY;   /* from anywhere   */

    /* Bind the server socket to our port */
    if (bind(sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr)) == -1)
    {
        fprintf(stderr, "ERROR: failed to bind\n");
        return -1;
    }

    /* Listen for a new connection, allow 5 pending connections */
    if (listen(sockfd, 5) == -1)
    {
        fprintf(stderr, "ERROR: failed to listen\n");
        return -1;
    }

    /* Continue to accept clients until shutdown is issued */
    while (!shutdown)
    {
        printf("Waiting for a connection...\n");

        /* Accept client connections */
        if ((connd = accept(sockfd, (struct sockaddr *)&clientAddr, &size)) == -1)
        {
            fprintf(stderr, "ERROR: failed to accept the connection\n\n");
            return -1;
        }

        /* Create a WOLFSSL object */
        if ((ssl = wolfSSL_new(ctx)) == NULL)
        {
            fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
            return -1;
        }

        /* Attach wolfSSL to the socket */
        wolfSSL_set_fd(ssl, connd);

        /* Establish TLS connection */
        ret = wolfSSL_accept(ssl);
        if (ret != SSL_SUCCESS)
        {
            fprintf(stderr, "wolfSSL_accept error = %d\n",
                    wolfSSL_get_error(ssl, ret));
            return -1;
        }

        printf("Client connected successfully\n");
        pthread_t mainThread;
        pthread_create(&mainThread,NULL,ClientHandler,NULL);
        pthread_join(mainThread,NULL);
    }

    printf("Shutdown complete\n");

    /* Cleanup after this connection */
    wolfSSL_free(ssl); /* Free the wolfSSL object              */
    close(connd);      /* Close the connection to the client   */
    /* Cleanup and return */

    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(sockfd);         /* Close the socket listening for clients   */
    return 0;              /* Return reporting a success               */
}
