#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "connection.h"

#define TRUE 1
#define FALSE 0

// Function that rechecks for new sockets that should receive messages
void checkForNewSocks(char allSocks[MAX_AMOUNT_OF_SOCKETS][strlen(SOCKET_NAME_TEMPLATE) + 2]){
    char testIfAvailableSocket[strlen(SOCKET_NAME_TEMPLATE) + (MAX_AMOUNT_OF_SOCKETS / 10) + 2];
    char idOfReader[(MAX_AMOUNT_OF_SOCKETS / 10) + 2];

    for (int i = 0; i < MAX_AMOUNT_OF_SOCKETS; i++){
        strcpy(testIfAvailableSocket, SOCKET_NAME_TEMPLATE);
        sprintf(idOfReader, "%d", i);
        strcat(testIfAvailableSocket, idOfReader);

        if (access(testIfAvailableSocket, F_OK) == 0) {
            strcpy(allSocks[i], testIfAvailableSocket);
        } else {
            strcpy(allSocks[i], "-1");
        }
    }
}

int main(int argc, char *argv[]){

    int returnValue;

    // Stores the path to each socket
    char allSocks[MAX_AMOUNT_OF_SOCKETS][strlen(SOCKET_NAME_TEMPLATE) + 2];

    // Stores all socket connections
    struct sockaddr_un socks[MAX_AMOUNT_OF_SOCKETS];
    int writeSockets[MAX_AMOUNT_OF_SOCKETS];

    // Buffer for messages to be sent
    char sendMessageBuffer[MAX_MESSAGE_LENGTH];

    while (TRUE){

        // Clear message buffer
        memset(&sendMessageBuffer, 0, sizeof(sendMessageBuffer));
        scanf(" %1021[^\n]", sendMessageBuffer);
        printf("Sending: %s\n", sendMessageBuffer);

        // Determine all available sockets
        checkForNewSocks(allSocks);

        // Establish all connections first
        for (int i = 0; i < MAX_AMOUNT_OF_SOCKETS; i++){
        
            // Skip spots without sockets
            if (strcmp(allSocks[i], "-1") == 0){
                continue;
            }

            // Establish a writer socket
            writeSockets[i] = socket(AF_UNIX, SOCK_SEQPACKET, 0);
            if (writeSockets[i] == -1) {
                perror("socket");
                exit(EXIT_FAILURE);
            }

            // Set some standard settings: Clear all default fields, Define that the socket is a Unix Domain Socket, Provide correct path to socket
            memset(&socks[i], 0, sizeof(allSocks[i]));
            socks[i].sun_family = AF_UNIX;
            strncpy(socks[i].sun_path, allSocks[i], sizeof(socks[i].sun_path) - 1);

            // Connect with the socket
            returnValue = connect(writeSockets[i], (const struct sockaddr *) &socks[i], sizeof(socks[i]));
            if (returnValue == -1){
                perror("connect");
                exit(EXIT_FAILURE);
            }
        }
        // All sockets have now been connected

        for (int i = 0; i < MAX_AMOUNT_OF_SOCKETS; i++){
            // Skip spots without sockets
            if (strcmp(allSocks[i], "-1") == 0){
                continue;
            }

            // Send the message to each socket individually
            returnValue = write(writeSockets[i], sendMessageBuffer, strlen(sendMessageBuffer));
            if (returnValue == -1) {
                perror("write");
                exit(EXIT_FAILURE);
            }
        }
    }

    return 0;
}