#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "transfer.h"
/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

void writefile(WOLFSSL *ssl, FILE *fp);
ssize_t total = 0;
int main(int argc, char *argv[])
{
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    /* Initialize wolfSSL */
    wolfSSL_Init();
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        perror("Can't allocate sockfd");
        exit(1);
    }
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL)
    {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        return -1;
    }

    /* Load CA certificates into CYASSL_CTX */
    if (wolfSSL_CTX_load_verify_locations(ctx, "./certs/ca-cert.pem", 0) != SSL_SUCCESS)
    {
        fprintf(stderr, "Error loading ./certs/ca-cert.pem, please check the file.\n");
        exit(EXIT_FAILURE);
    }

    /* Load server certificates into WOLFSSL_CTX */
    if (wolfSSL_CTX_use_certificate_file(ctx, "./certs/server-cert.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS)
    {
        fprintf(stderr, "Error loading ./certs/server-cert.pem, please check the file.\n");
        exit(EXIT_FAILURE);
    }
    /* Load keys */
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, "./certs/server-key.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS)
    {
        fprintf(stderr, "Error loading ./certs/server-key.pem, please check the file.\n");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in clientaddr, serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons(SERVERPORT);

    if (bind(sockfd, (const struct sockaddr *)&serveraddr, sizeof(serveraddr)) == -1)
    {
        perror("Bind Error");
        exit(1);
    }

    if (listen(sockfd, LINSTENPORT) == -1)
    {
        perror("Listen Error");
        exit(1);
    }

    socklen_t addrlen = sizeof(clientaddr);
    int connfd = accept(sockfd, (struct sockaddr *)&clientaddr, &addrlen);
    if (connfd == -1)
    {
        perror("Connect Error");
        exit(1);
    }
    close(sockfd);
    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL)
    {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        return -1;
    }
    /* Attach wolfSSL to the socket */
    wolfSSL_set_fd(ssl, connfd);
    /* Establish TLS connection */
    int ret = wolfSSL_accept(ssl);
    if (ret != SSL_SUCCESS)
    {
        fprintf(stderr, "wolfSSL_accept error = %d\n", wolfSSL_get_error(ssl, ret));
        return -1;
    }

    char filename[BUFFSIZE] = {0};
    if (wolfSSL_read(ssl, filename, sizeof(filename)) < 0)
    {
        perror("Can't receive filename");
        exit(1);
    }

    FILE *fp = fopen("output.txt", "wb");
    if (fp == NULL)
    {
        perror("Can't open file");
        exit(1);
    }

    char addr[INET_ADDRSTRLEN];
    printf("Start receive file: %s from %s\n", filename, inet_ntop(AF_INET, &clientaddr.sin_addr, addr, INET_ADDRSTRLEN));
    writefile(ssl, fp);
    printf("Receive Success, NumBytes = %ld\n", total);
    wolfSSL_free(ssl);     /* Free the wolfSSL object              */
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    fclose(fp);
    close(connfd);
    return 0;
}

void writefile(WOLFSSL *ssl, FILE *fp)
{
    ssize_t n;
    char buff[MAX_LINE] = {0};
    clock_t t,sum = 0;
    t = clock();
    while ((n = wolfSSL_read(ssl, buff, sizeof(buff))) > 0)
    {
        sum += clock() - t;
        total += n;
        if (n == -1)
        {
            perror("Receive File Error");
            exit(1);
        }
        if (fwrite(buff, sizeof(char), n, fp) != n)
        {
            perror("Write File Error");
            exit(1);
        }
        memset(buff, 0, MAX_LINE);
        t = clock();
    }
    //t = clock() - t;
    double time_taken = ((double)sum) / CLOCKS_PER_SEC; // in seconds
    printf("%f seconds to receive data \n", time_taken);
}
