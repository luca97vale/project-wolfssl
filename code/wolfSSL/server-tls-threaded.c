/* server-tls-threaded.c
 * Luca Valentini
 * luca.valentini@studenti.polito.it
 * Information System Security
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

//Global variables
int counter = 0; //counter of connected clients
pthread_t Taccept;
pthread_t Treader;
int sockfd;
struct sockaddr_in servAddr;
WOLFSSL_CTX *ctx;

struct communication
{
    WOLFSSL *ssl;
    size_t len;
    pthread_t Taccept;
    int connd;
    struct sockaddr_in clientAddr;
    socklen_t size;
    char buffReader[256];
    char username[256];
};

struct communication clients[10];

void removeClient(int id)
{
    /* Cleanup after this connection */
    wolfSSL_free(clients[id].ssl); /* Free the wolfSSL object              */
    close(clients[id].connd);      /* Close the connection to the client   */
    clients[id].ssl = NULL;
}

void *readBuffer(void *args)
{
    int ret, i;
    int id = *((int *)args);
    //Read the username
    XMEMSET(clients[id].buffReader, 0, sizeof(clients[id].buffReader));
    ret = wolfSSL_read(clients[id].ssl, clients[id].buffReader, sizeof(clients[id].buffReader) - 1);
    strcpy(clients[id].username, clients[id].buffReader);

    while (1)
    {
        /* Read the client data into our buff array */
        XMEMSET(clients[id].buffReader, 0, sizeof(clients[id].buffReader));
        if (clients[id].ssl != NULL)
        {
            ret = wolfSSL_read(clients[id].ssl, clients[id].buffReader, sizeof(clients[id].buffReader) - 1);

            if (ret > 0)
            {
                if (!strcmp(clients[id].buffReader, "quit"))
                {
                    removeClient(id);
                    pthread_exit(NULL); /* End threaded execution                */
                }
                else if (!strcmp(clients[id].buffReader, "list"))
                {
                    wolfSSL_write(clients[id].ssl, "Server", XSTRLEN("Server"));
                    wolfSSL_write(clients[id].ssl, "Connected clients:", XSTRLEN("Connected clients:"));
                    for (int j = 0; j < counter; j++)
                    {
                        if (j != id)
                        {
                            char num[50];
                            sprintf(num, "%d", j);
                            wolfSSL_write(clients[id].ssl, num, XSTRLEN(num));
                            wolfSSL_write(clients[id].ssl, clients[j].username, XSTRLEN(clients[j].username));
                        }
                    }
                }
                else if (clients[id].buffReader[0] == '#')
                {
                    int dest = clients[id].buffReader[1] - 48;      //ASCII
                    if (dest<= counter && dest >= 0)
                    {
                        char str[255];
                        strcpy(str,"private-");
                        strcat(str,clients[id].username);
                        ret = wolfSSL_write(clients[dest].ssl, str, XSTRLEN(str));
                        strcpy(str,clients[id].buffReader+2);
                        ret = wolfSSL_write(clients[dest].ssl, str, XSTRLEN(str));
                    }
                }
                else
                {
                    printText(clients[id].buffReader, clients[id].username);
                    int len = XSTRLEN(clients[id].buffReader);
                    for (i = 0; i < counter; i++)
                    {
                        if (i != id)
                        {
                            ret = wolfSSL_write(clients[i].ssl, clients[id].username, XSTRLEN(clients[id].username));
                            ret = wolfSSL_write(clients[i].ssl, clients[id].buffReader, len);
                        }
                    }
                }
            }
            else
            {
                printText("ERROR READ!!", "System");
                pthread_exit(NULL); /* End theread execution                */
            }
        }
    }
    free(args);
}

void *acceptConnection(void *args)
{
    int ret;
    ncurses_start();
    clearWin();
    while (1)
    {
        //printText("Waiting for a connection...\n","System");
        /* Accept client connections */
        clients[counter].size = sizeof(clients[counter].clientAddr);
        if ((clients[counter].connd = accept(sockfd, (struct sockaddr *)&clients[counter].clientAddr, &clients[counter].size)) == -1)
        {
            fprintf(stderr, "ERROR: failed to accept the connection\n\n");
            return NULL;
        }

        /* Create a WOLFSSL object */
        if ((clients[counter].ssl = wolfSSL_new(ctx)) == NULL)
        {
            fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
            return NULL;
        }

        /* Attach wolfSSL to the socket */
        wolfSSL_set_fd(clients[counter].ssl, clients[counter].connd);

        /* Establish TLS connection */
        ret = wolfSSL_accept(clients[counter].ssl);
        if (ret != SSL_SUCCESS)
        {
            ncurses_end();
            fprintf(stderr, "wolfSSL_accept error = %d\n",
                    wolfSSL_get_error(clients[counter].ssl, ret));
            return NULL;
        }
        printText("Client connected successfully\n", "System");
        int *argCounter = malloc(sizeof(*argCounter));
        if (argCounter == NULL)
        {
            fprintf(stderr, "Couldn't allocate memory for thread arg.\n");
            exit(EXIT_FAILURE);
        }

        *argCounter = counter;
        if (pthread_create(&Treader, NULL, readBuffer, argCounter))
        {
            fprintf(stderr, "Error creating thread\n");
            fflush(stdout);
            return NULL;
        }
        counter++;
    }
}

int main()
{
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
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
        printf("setsockopt(SO_REUSEADDR) failed");
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

    /* Listen for a new connection */
    if (listen(sockfd, 10) == -1)
    {
        fprintf(stderr, "ERROR: failed to listen\n");
        return -1;
    }

    if (pthread_create(&Taccept, NULL, acceptConnection, NULL))
    {
        fprintf(stderr, "Error creating thread\n");
        fflush(stdout);
        return -1;
    }

    pthread_join(Taccept, NULL);

    return 0;
}