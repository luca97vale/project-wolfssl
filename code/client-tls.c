/* client-tls.c
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

#define DEFAULT_PORT 11111

#define CERT_FILE "./certs/ca-cert.pem"

//Global variables
char *ip;

void *client(void *a)
{
    int sockfd;
    struct sockaddr_in servAddr;
    char buff[256];
    char username[20];
    size_t len;

    /* declare wolfSSL objects */
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;

    printf("Set your username: ");
    if (fgets(username, sizeof(username), stdin) == NULL)
    {
        fprintf(stderr, "ERROR: failed to get message for server\n");
        return NULL;
    }

    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        return NULL;
    }

    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL)
    {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        return NULL;
    }

    /* Load client certificates into WOLFSSL_CTX */
    if (wolfSSL_CTX_load_verify_locations(ctx, CERT_FILE, NULL) != SSL_SUCCESS)
    {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                CERT_FILE);
        return NULL;
    }

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family = AF_INET;           /* using IPv4      */
    servAddr.sin_port = htons(DEFAULT_PORT); /* on DEFAULT_PORT */

    /* Get the server IPv4 address from the command line call */
    if (inet_pton(AF_INET, ip, &servAddr.sin_addr) != 1)
    {
        fprintf(stderr, "ERROR: invalid address\n");
        return NULL;
    }

    /* Connect to the server */
    if (connect(sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr)) == -1)
    {
        fprintf(stderr, "ERROR: failed to connect\n");
        return NULL;
    }

    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL)
    {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        return NULL;
    }

    /* Attach wolfSSL to the socket */
    wolfSSL_set_fd(ssl, sockfd);

    /* Connect to wolfSSL on the server side */
    if (wolfSSL_connect(ssl) != SSL_SUCCESS)
    {
        fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
        return NULL;
    }

    strtok(username, "\n");
    len = strnlen(username, sizeof(username));
    /* Send the username to the server */
    if (wolfSSL_write(ssl, username, len) != len)
    {
        fprintf(stderr, "ERROR: failed to write\n");
        return NULL;
    }

    /* Get a message for the server from stdin */
    printf("Message for server: ");
    memset(buff, 0, sizeof(buff));
    if (fgets(buff, sizeof(buff), stdin) == NULL)
    {
        fprintf(stderr, "ERROR: failed to get message for server\n");
        return NULL;
    }
    len = strnlen(buff, sizeof(buff));

    /* Send the message to the server */
    if (wolfSSL_write(ssl, buff, len) != len)
    {
        fprintf(stderr, "ERROR: failed to write\n");
        return NULL;
    }

    /* Read the server data into our buff array */
    memset(buff, 0, sizeof(buff));
    if (wolfSSL_read(ssl, buff, sizeof(buff) - 1) == -1)
    {
        fprintf(stderr, "ERROR: failed to read\n");
        return NULL;
    }

    /* Print to stdout any data the server sends */
    printf("Server: %s\n", buff);

    /* Cleanup and return */
    wolfSSL_free(ssl);     /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(sockfd);         /* Close the connection to the server       */
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t Twrite;

    /* Check for proper calling convention */
    if (argc != 2)
    {
        printf("usage: %s <IPv4 address>\n", argv[0]);
        return -1;
    }

    ip = argv[1];

    /* create a second thread which executes inc_x(&x) */
    int a = 0;
    if (pthread_create(&Twrite, NULL, client, (void *)&a))
    {

        fprintf(stderr, "Error creating thread\n");
        fflush(stdout);
        return 1;
    }

    if (pthread_join(Twrite, NULL))
    {

        fprintf(stderr, "Error joining thread\n");
        return 2;
    }

    return 0; /* Return reporting a success               */
}
