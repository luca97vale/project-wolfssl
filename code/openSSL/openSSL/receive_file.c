#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "transfer.h"
#include <openssl/ssl.h>
void writefile(SSL *ssl, FILE *fp);
ssize_t total = 0;
int main(int argc, char *argv[])
{
    SSL_CTX *ctx;
    SSL *ssl;
    SSL_library_init();
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        perror("Can't allocate sockfd");
        exit(1);
    }
    ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
    if (ctx == NULL)
    {
        fprintf(stderr, "ERROR: failed to create SSL_CTX\n");
        return -1;
    }

    if (SSL_CTX_load_verify_locations(ctx, "./certs/CA-cert.pem", 0) != 1)
    {
        fprintf(stderr, "Error loading ./certs/ca-cert.pem, please check the file.\n");
        return -1;
    }

    if (SSL_CTX_use_certificate_file(ctx, "./certs/server-cert.pem", SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Error loading ./certs/servercert.pem, please check the file.\n");
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "./certs/server-key.pem", SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Error loading ./certs/serverkey.pem, please check the file.\n");
        return -1;
    }

    //SSL_CTX_set_options(ctx,SSL_OP_NO_TICKET);

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

    if ((ssl = SSL_new(ctx)) == NULL)
    {
        fprintf(stderr, "ERROR: failed to create SSL object\n");
        return -1;
    }
    SSL_set_fd(ssl, connfd);

    /* Establish TLS connection */
    int ret = SSL_accept(ssl);
    if (ret < 0)
    {
        fprintf(stderr, "SSL_accept error = %d\n", SSL_get_error(ssl, ret));
        return -1;
    }

    char filename[BUFFSIZE] = {0};
    if (recv(connfd, filename, BUFFSIZE, 0) == -1)
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

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    fclose(fp);
    close(connfd);
    return 0;
}

void writefile(SSL *ssl, FILE *fp)
{
    ssize_t n;
    char buff[MAX_LINE] = {0};
    while ((n = SSL_read(ssl, buff, sizeof(buff))) > 0)
    {
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
    }
}
