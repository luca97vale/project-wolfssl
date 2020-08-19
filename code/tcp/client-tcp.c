/* client-tcp.c
 * Luca Valentini
 * luca.valentini@studenti.polito.it
 * Information System Security
 */

/* the usual suspects */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <ncurses.h>

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

#define DEFAULT_PORT 50000


//Global variables
char *ip;
int sockfd;
char buff[256];
char buffReader[256];
size_t len;
int is_end = 0;
char username[20];
extern char Rbuffer[256];
//create Thread Writer
pthread_t Twriter;
//create Thread Reader
pthread_t Treader;

void *writeBuffer(void *args)
{
    while (!is_end)
    {
        /* Get a message for the server from stdin */
        memset(Rbuffer, 0, sizeof(Rbuffer));
        read_in();
        len = strnlen(Rbuffer, sizeof(Rbuffer));
        if (XSTRNCMP(Rbuffer, "quit", 4) == 0)
        {
            is_end = 1;
        }
        /* Send the message to the server */
        if (write(sockfd, Rbuffer, len) != len)
        {
            fprintf(stderr, "ERROR: failed to write\n");
            return NULL;
        }
        printText(Rbuffer, username);
    }
    return NULL;
}

void *readBuffer(void *args)
{
    while (!is_end)
    {
        /* Read the server data into our buff array */
        memset(buffReader, 0, sizeof(buffReader));
        if (read(sockfd, buffReader, sizeof(buffReader) - 1) == -1)
        {
            fprintf(stderr, "ERROR: failed to read\n");
            pthread_cancel(Twriter);
            return NULL;
        }
        else
        {
            printText(buffReader, "Server");
        }
    }
    return NULL;
}

void *client(void *args)
{
    struct sockaddr_in servAddr;

    printf("Set your username: ");
    refresh();
    if (!scanf("%s", username))
    {
        fprintf(stderr, "ERROR: failed to get message for server\n");
        getch();
        return NULL;
    }
    ncurses_start();

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        fprintf(stderr, "ERROR: failed to create the socket\n");
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
        printText("ERROR: failed to connect", "System");
        return NULL;
    }
    /*Do something*/

    strtok(username, "\n");
    len = strnlen(username, sizeof(username));
    /* Send the username to the server */

    if (write(sockfd, username, len) != len)
    {
        fprintf(stderr, "ERROR: failed to write\n");
        return NULL;
    }
    getch();

    if (pthread_create(&Twriter, NULL, writeBuffer, NULL))
    {
        fprintf(stderr, "Error creating thread\n");
        fflush(stdout);
        return NULL;
    }

    if (pthread_create(&Treader, NULL, readBuffer, NULL))
    {
        fprintf(stderr, "Error creating thread\n");
        fflush(stdout);
        return NULL;
    }

    pthread_join(Twriter, NULL);
    pthread_cancel(Treader);
    pthread_join(Treader, NULL);

    close(sockfd); /* Close the connection to the server       */
    printText("Communication is ended!\n Press a button!!!", "System");
    getch();
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t Tclient;
    /* Check for proper calling convention */
    if (argc != 2)
    {
        printf("usage: %s <IPv4 address>\n", argv[0]);
        return -1;
    }

    ip = argv[1];

    /* create a second thread which executes inc_x(&x) */
    if (pthread_create(&Tclient, NULL, client, NULL))
    {

        fprintf(stderr, "Error creating thread\n");
        fflush(stdout);
        return 1;
    }

    if (pthread_join(Tclient, NULL))
    {

        fprintf(stderr, "Error joining thread\n");
        return 2;
    }
    ncurses_end();
    return 0; /* Return reporting a success               */
}