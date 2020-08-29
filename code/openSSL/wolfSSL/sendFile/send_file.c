#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "transfer.h"
/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

void sendfile(FILE *fp, WOLFSSL *ssl);
ssize_t total = 0;

int main(int argc, char *argv[])
{
    /* declare wolfSSL objects */
    WOLFSSL_CTX *ctx;
    WOLFSSL *ssl;
    if (argc != 3)
    {
        perror("usage:send_file filepath <IPaddress>");
        exit(1);
    }
    /* Initialize wolfSSL */
    wolfSSL_Init();

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("Can't allocate sockfd");
        exit(1);
    }
    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL)
    {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        return -1;
    }

    /* Load CA certificates into WOLFSSL_CTX */
    if (wolfSSL_CTX_load_verify_locations(ctx, "./certs/ca-cert.pem", 0) != SSL_SUCCESS)
    {
        fprintf(stderr, "Error loading ./certs/ca-cert.pem, please check the file.\n");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(SERVERPORT);
    if (inet_pton(AF_INET, argv[2], &serveraddr.sin_addr) < 0)
    {
        perror("IPaddress Convert Error");
        exit(1);
    }

    if (connect(sockfd, (const struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
    {
        perror("Connect Error");
        exit(1);
    }

    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL)
    {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        return -1;
    }

    /* Attach wolfSSL to the socket */
    wolfSSL_set_fd(ssl, sockfd);
    /* Connect to wolfSSL on the server side */
    if (wolfSSL_connect(ssl) != SSL_SUCCESS)
    {
        fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
        return -1;
    }

    char *filename = basename(argv[1]);
    if (filename == NULL)
    {
        perror("Can't get filename");
        exit(1);
    }

    char buff[BUFFSIZE] = {0};
    strncpy(buff, filename, strlen(filename));
    if (send(sockfd, buff, BUFFSIZE, 0) == -1)
    {
        perror("Can't send filename");
        exit(1);
    }

    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL)
    {
        perror("Can't open file");
        exit(1);
    }

    sendfile(fp, ssl);
    //puts("Send Success");
    printf("Send Success, NumBytes = %ld\n", total);
    fclose(fp);
    /* Cleanup and return */
    wolfSSL_free(ssl);     /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx); /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();     /* Cleanup the wolfSSL environment          */
    close(sockfd);         /* Close the connection to the server       */
    return 0;
}

void sendfile(FILE *fp, WOLFSSL *ssl)
{
    int n;
    char sendline[MAX_LINE] = {0};
    while ((n = fread(sendline, sizeof(char), MAX_LINE, fp)) > 0)
    {
        total += n;
        if (n != MAX_LINE && ferror(fp))
        {
            perror("Read File Error");
            exit(1);
        }
        if (wolfSSL_write(ssl, sendline, strlen(sendline)) < 0)
        {
            perror("Can't send file");
            exit(1);
        }
        memset(sendline, 0, MAX_LINE);
    }
}
