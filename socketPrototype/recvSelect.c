#include <asm-generic/socket.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "connection.h"

// Signal handler to correctly close all sockets
volatile sig_atomic_t continueRead = 1;
void sigint_closeAllSockets (int sig) {
    continueRead = 0;
    //signal(sig, sigint_closeAllSockets);
}

int main (int argc, char *argv[]){
    int maxClients = MAX_AMOUNT_OF_SOCKETS;
    int readSocket, newSocket, clientSocket[maxClients];
    int activity;
    int returnValue;
    int sd, max_sd;
    int addressLength;
    struct sockaddr_un address;

    int opt = 1;

    char buffer[MAX_MESSAGE_LENGTH];

    fd_set readfds;

    // Set default: No socket is connected
    int i;
    for (i = 0; i < maxClients; i++){
        clientSocket[i] = 0;
    }

    // Define sa_handler struct for signal handler
    struct sigaction signalHandlerStruct;
    // Initiate desired settings
    signalHandlerStruct.sa_handler = sigint_closeAllSockets;
    sigemptyset(&signalHandlerStruct.sa_mask);
    signalHandlerStruct.sa_flags = SA_RESTART;

    // Figure out current read socket address
    i = 0;
    char idOfReader[8];
    char currSockAddress[strlen(SOCKET_NAME_TEMPLATE) + 2];
    while (1){
        strcpy(currSockAddress, SOCKET_NAME_TEMPLATE);
        sprintf(idOfReader, "%d", i);
        strcat(currSockAddress, idOfReader);
        if (access(currSockAddress, F_OK) == 0){
            i++;
            continue;
        }else{
            // We want to use this previously unused socket
            break;
        }
    }
    printf("Using this adress: %s\n", currSockAddress);

    // Create unix domain socket
    readSocket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (readSocket == -1){
        perror("Could not create local socket");
        exit(EXIT_FAILURE);
    }

    // Clearing all fields
    memset(&address, 0, sizeof(address));

    // Allowing multiple connections
    returnValue = setsockopt(readSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
    if (returnValue < 0){
        perror("Could not configure read socket settings");
        exit(EXIT_FAILURE);
    }

    // Setting fields of struct to appropriate Values
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, currSockAddress, sizeof(address.sun_path) - 1);

    // Binding local socket to unix domain socket
    returnValue = bind(readSocket, (const struct sockaddr *) &address, sizeof(address));
    if (returnValue == -1){
        perror("Could not bind to local socket");
        exit(EXIT_FAILURE);
    }

    returnValue = listen(readSocket, 3);
    if (returnValue < 0){
        perror("Could not listen for clients");
        exit(EXIT_FAILURE);
    }

    // Accepting connections
    addressLength = sizeof(address);
    puts("Waiting for connections...");

    // Start signal handler
    if (sigaction(SIGINT, &signalHandlerStruct, NULL) == -1){
        perror("signal handler");
        exit(EXIT_FAILURE);
    }
    // This will close all sockets once all writers are finished

    while(continueRead){

        // Clear list of sockets to poll from
        FD_ZERO(&readfds);

        // Adding read socket to list
        FD_SET(readSocket, &readfds);

        // Read socket is currently the only socket; therefore the one with the highest socket descriptor
        max_sd = readSocket;

        // Add clients
        for (i = 0; i < maxClients; i++){
            
            // To make upcoming code more readable
            sd = clientSocket[i];

            // If sd is valid -> Add to list
            if (sd > 0){
                FD_SET(sd, &readfds);
            }

            // Dertemine highest file descriptor number
            if (sd > max_sd){
                max_sd = sd;
            }
        }
        // All current clients have now been added/updated

        // Wait for I/O on socket; Skip read socket
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);
        if ((activity < 0) && (errno!=EINTR)){
            perror("Could not select a socket");
        }

        // New connection is ready to be accepted
        if (FD_ISSET(readSocket, &readfds)){
            newSocket = accept(readSocket, (struct sockaddr *)&address, (socklen_t*)&addressLength);
            if (newSocket < 0){
                perror("Could not accept connection");
                exit(EXIT_FAILURE);
            }

            // Add this connection to array of client sockets
            for (i = 0; i < maxClients; i++){
                // Connection must be empty
                if (clientSocket[i] == 0){
                    clientSocket[i] = newSocket;
                    break;
                }
            }
        }

        // It may be a different I/O operation
        for (i = 0; i < maxClients; i++){
            sd = clientSocket[i];

            if (FD_ISSET(sd, &readfds)){
                // Check if it was a close operation
                returnValue = read(sd, buffer, 1024);
                if (returnValue == 0){
                    // Check who disconnected
                    getpeername(sd, (struct sockaddr*)&address, (socklen_t*)&addressLength);

                    // Close the socket on receiver side
                    close(sd);
                    clientSocket[i] = 0;
                }else{
                    buffer[returnValue] = '\0';
                    printf("I read: %s\n", buffer);
                }
            }
        }
    }
    printf("%d\n", continueRead);
    close(readSocket);
    unlink(currSockAddress);
    return 0;
}