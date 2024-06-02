#include "include/sock_comm.h"
#include "io_ipc.h"
#include <math.h>

int sock_init(struct sock_writer_arg_t *sock_arg, int role){
    // Check if path to unix domain socket is compliant with the SOCKET_TEMPLATE_LENGTH
    if ((strlen(SOCKET_NAME_TEMPLATE) +
        ((int) floor (log10 (abs (MAX_AMOUNT_OF_SOCKETS))) + 1))
            >= SOCKET_TEMPLATE_LENGTH){
        perror("filepath to socket is too long for default maximum path length");
        exit(EXIT_FAILURE);
    }

    // Establish all common attributes for each of these connections
    int numberOfDigitsInMaxSockets = ((int) floor (log10 (MAX_AMOUNT_OF_SOCKETS)) + 2);
    char idOfReader[numberOfDigitsInMaxSockets];

    // Initialize all necessary args
    for (int i = 0; i < MAX_AMOUNT_OF_SOCKETS; i++){

        // Provide them with the template name
        strcpy(sock_arg->socketPathNames[i], SOCKET_NAME_TEMPLATE);
        sprintf(idOfReader, "%d", i);
        strcat(sock_arg->socketPathNames[i], idOfReader);

        // Ensure that socket is closed from leftover application of this program
        //unlink(sock_arg->socketPathNames[i]);

        /**
            * Set some standard settings:
            * Clear all default fields
            * Define that the socket is a Unix Domain Socket
            * Provide correct path to socket
        */
        sock_arg->socketConnections[i].sun_family = AF_UNIX;
        strncpy(sock_arg->socketConnections[i].sun_path, sock_arg->socketPathNames[i], sizeof(sock_arg->socketConnections[i].sun_path) - 1);

        // No connections have been established yet
        sock_arg->writeSockets[i] = -1;
        sock_arg->socketRecvs[i] = -1;
    }

    return IO_IPC_SUCCESS;
}

int sock_writev(struct sock_writer_arg_t *sock_arg, struct iovec *log_iovs, uint16_t invalid_count, uint16_t numOfSocks){
    // To check for errors
    int retval_ipc;

    // Check if there are new sockets to send to
    for (int i = 0; i < numOfSocks; i++){
        if (sock_arg->socketRecvs[i] == 1){
            continue;
        }
        if (access(sock_arg->socketPathNames[i], F_OK) == 0){
            sock_arg->socketRecvs[i] = 0;
        }else{
            sock_arg->socketRecvs[i] = -1;
        }
    }

    // Establish all connections first
    for (int i = 0; i < numOfSocks; i++){
        
        // Skip spots without sockets or already established sockets
        if (sock_arg->socketRecvs[i] != 0){
            continue;
        }

        // Establish a writer socket
        sock_arg->writeSockets[i] = socket(AF_UNIX, SOCK_SEQPACKET, 0);
        if (sock_arg->writeSockets[i] == -1) {
            return IO_IPC_SOCK_ERR;
        }

        // Connect with the new unix domain socket
        retval_ipc = connect(sock_arg->writeSockets[i], (const struct sockaddr *) &sock_arg->socketConnections[i], sizeof(sock_arg->socketConnections[i]));
        if (retval_ipc == -1){
            return IO_IPC_SOCK_ERR;
        }

        // Set flag to remember that this socket is being sent to
        sock_arg->socketRecvs[i] = 1;
    }
    // All available sockets will now receive all data


    // Send data
    for (int j = 0; j < invalid_count; j++){

        // Send the message to each socket individually
        for (int i = 0; i < numOfSocks; i++){
        
            // Skip spots without sockets
            if (sock_arg->socketRecvs[i] != 1){
                // This can not be break since we can not guarantee that sockets will close in the order they were opened
                continue;
            }
        
            // Send iovec buffer filled with log messages
            retval_ipc = write(sock_arg->writeSockets[i], log_iovs[j].iov_base, log_iovs[j].iov_len);
            if (retval_ipc == -1) {
                return IO_IPC_SOCK_ERR;
            }
        }
    }

    // The number of logged messages is returned
    return invalid_count;
}

int sock_finalize(struct sock_writer_arg_t *sock_args, int role){
    for (int i = 0; i < MAX_AMOUNT_OF_SOCKETS; i++){
        unlink(sock_args->socketPathNames[i]);
    }
    return IO_IPC_SUCCESS;
}

int sock_cleanup(){
    return 0;
}