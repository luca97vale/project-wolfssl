#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "transfer.h"
#include <openssl/ssl.h>

void sendfile(FILE *fp, SSL *ssl);
ssize_t total = 0;
SSL_CTX *ctx;
int main(int argc, char *argv[])
{
    SSL *ssl;
    if (argc != 3)
    {
        perror("usage:send_file filepath <IPaddress>");
        exit(1);
    }

    SSL_library_init();

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("Can't allocate sockfd");
        exit(1);
    }


    if ((ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)
    {
        fprintf(stderr, "ERROR: failed to create SSL_CTX\n");
        return -1;
    }
    SSL_CTX_set_options(ctx,SSL_OP_NO_TLSv1_3);

    if (SSL_CTX_load_verify_locations(ctx, "./certs/CA-cert.pem", 0) != 1)
    {
        fprintf(stderr, "Error loading ./certs/cacert.pem, please check the file.\n");
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

    if ((ssl = SSL_new(ctx)) == NULL)
    {
        fprintf(stderr, "ERROR: failed to create SSL object\n");
        return -1;
    }

    /* Attach SSL to the socket */
    SSL_set_fd(ssl, sockfd);
    /* Connect to SSL on the server side */
    if (SSL_connect(ssl) < 0)
    {
        fprintf(stderr, "ERROR: failed to connect to SSL\n");
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
    if (SSL_write(ssl, buff, strlen(buff)) == -1)
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
    printf("Send Success, NumBytes = %d\n", total);
    fclose(fp);
    close(sockfd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}

void sendfile(FILE *fp, SSL *ssl)
{
    int n;
    char sendline[MAX_LINE];
    clock_t t, sum = 0;
    t = clock();
    while ((n = fread(sendline, sizeof(char), MAX_LINE - 1, fp)) > 0)
    {
        if (n != MAX_LINE && ferror(fp))
        {
            perror("Read File Error");
            exit(1);
        }
        t = clock();
        if ((total += SSL_write(ssl, sendline, n)) < 0)
        {
            perror("Can't send file");
            exit(1);
        }
        sum += clock() - t;
        memset(sendline, 0, MAX_LINE);
    }
    double time_taken = ((double)sum) / CLOCKS_PER_SEC; // in seconds
    printf("%f seconds to send data \n", time_taken);
}
