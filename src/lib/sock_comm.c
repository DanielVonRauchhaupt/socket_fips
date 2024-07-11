#include "include/sock_comm.h"
#include "io_ipc.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/uio.h>

int sock_init(union sock_arg_t *sock_args, int role){

    if (role == SOCK_WRITER){

        // Check if path to unix domain socket is compliant with the SOCKET_TEMPLATE_LENGTH
        if ((strlen(SOCKET_NAME_TEMPLATE) +
            ((int) floor (log10 (abs (MAX_AMOUNT_OF_SOCKETS))) + 1))
                >= SOCKET_TEMPLATE_LENGTH){
            return IO_IPC_SOCK_SET;
        }

        // Establish all common attributes for each of these connections
        int numberOfDigitsInMaxSockets = ((int) floor (log10 (MAX_AMOUNT_OF_SOCKETS)) + 2);
        char idOfReader[numberOfDigitsInMaxSockets];

        // Initialize all necessary args
        for (int i = 0; i < MAX_AMOUNT_OF_SOCKETS; i++){

            // Provide them with the template name
            strcpy(sock_args->wargs.socketPathNames[i], SOCKET_NAME_TEMPLATE);
            sprintf(idOfReader, "%d", i);
            strcat(sock_args->wargs.socketPathNames[i], idOfReader);

            // Ensure that socket is closed from leftover application of this program
            //unlink(sock_args->wargs.socketPathNames[i]);

            /*
             * Set some standard settings:
             * Clear all default fields
             * Define that the socket is a Unix Domain Socket
             * Provide correct path to socket
             */
            sock_args->wargs.socketConnections[i].sun_family = AF_UNIX;
            strncpy(sock_args->wargs.socketConnections[i].sun_path, sock_args->wargs.socketPathNames[i], sizeof(sock_args->wargs.socketConnections[i].sun_path) - 1);

            // No connections have been established yet
            sock_args->wargs.writeSockets[i] = -1;
            sock_args->wargs.socketRecvs[i] = -1;
        }

        return IO_IPC_SUCCESS;
    
    }else{

        int clientSocketEstablished[MAX_AMOUNT_OF_SOCKETS];
		int readSocket;
		int returnValue;
		struct sockaddr_un address;

		int opt = 1;

		// Set default: No socket is connected
		for (int i = 0; i < MAX_AMOUNT_OF_SOCKETS; i++){
			clientSocketEstablished[i] = 0;
		}
		
		// We want to find the next available unused socket address
		int numberOfDigitsInMaxSockets = ((int) floor (log10 (MAX_AMOUNT_OF_SOCKETS)) + 2);
		char idOfReader[numberOfDigitsInMaxSockets];
		char currSockAddress[strlen(SOCKET_NAME_TEMPLATE) + numberOfDigitsInMaxSockets + 1];
		for (int i = 0; i < MAX_AMOUNT_OF_SOCKETS; i++){
			strcpy(currSockAddress, SOCKET_NAME_TEMPLATE);
			sprintf(idOfReader, "%d", i);
			strcat(currSockAddress, idOfReader);
			if (access(currSockAddress, F_OK) == 0){
				// Already exists, already in use
            	continue;
        	}else{
            	// We want to use this previously unused socket
				printf("Using:  %s\n", currSockAddress);
                fflush(stdout);
            	break;
        	}
		}
		strcpy(sock_args->rargs.socketPathName, currSockAddress);

		// Create the unix domain socket
		readSocket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
		if (readSocket == -1){
			return IO_IPC_SOCK_CON;
		}

		// Clearing all fields
    	memset(&address, 0, sizeof(address));

		// Allowing multiple connections
		returnValue = setsockopt(readSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
		if (returnValue < 0){
			return IO_IPC_SOCK_SET;
		}

		// Setting fields of struct to appropriate Values
		address.sun_family = AF_UNIX;
		strncpy(address.sun_path, currSockAddress, sizeof(address.sun_path) - 1);

		// Binding local socket to unix domain socket
		returnValue = bind(readSocket, (const struct sockaddr *) &address, sizeof(address));
		if (returnValue == -1){
			return IO_IPC_SOCK_CON;
		}

		// Set socket to listen only
		returnValue = listen(readSocket, 32);
		if (returnValue < 0){
			return IO_IPC_SOCK_CON;
		}

		// Setting sock_args struct
		sock_args->rargs.sizeOfAddressStruct = sizeof(address);
		sock_args->rargs.address = address;
        fcntl(readSocket, F_SETFL, fcntl(readSocket, F_GETFL, 0) | O_NONBLOCK);
		sock_args->rargs.readSocket = readSocket;
		for (int i = 0; i < MAX_AMOUNT_OF_SOCKETS; i++){
			sock_args->rargs.clientSockets[i] = clientSocketEstablished[i];
		}
    }

    return IO_IPC_SUCCESS;

}

int sock_writev(struct sock_writer_arg_t *sock_args, struct iovec *log_iovs, uint16_t invalid_count, uint16_t maxNumOfSocks){
    // To check for errors
    int retval_ipc;

    // Check if there are new sockets to send to
    for (int i = 0; i < maxNumOfSocks; i++){
        if (sock_args->socketRecvs[i] == 1){
            continue;
        }
        if (access(sock_args->socketPathNames[i], F_OK) == 0){
            sock_args->socketRecvs[i] = 0;
        }else{
            sock_args->socketRecvs[i] = -1;
        }
    }

    // Establish all connections first
    for (int i = 0; i < maxNumOfSocks; i++){
        
        // Skip spots without sockets or already established sockets
        if (sock_args->socketRecvs[i] != 0){
            continue;
        }

        // Establish a writer socket
        sock_args->writeSockets[i] = socket(AF_UNIX, SOCK_SEQPACKET, 0);
        if (sock_args->writeSockets[i] == -1) {
            return IO_IPC_SOCK_CON;
        }

        // Connect with the new unix domain socket
        retval_ipc = connect(sock_args->writeSockets[i], (const struct sockaddr *) &sock_args->socketConnections[i], sizeof(sock_args->socketConnections[i]));
        if (retval_ipc == -1){
            return IO_IPC_SOCK_CON;
        }

        // Set flag to remember that this socket is being sent to
        sock_args->socketRecvs[i] = 1;
    }
    // All available sockets will now receive all data


    // Send data
    for (int j = 0; j < invalid_count; j++){

        // Send the message to each socket individually
        for (int i = 0; i < maxNumOfSocks; i++){
        
            // Skip spots without sockets
            if (sock_args->socketRecvs[i] != 1){
                // This can not be break since we can not guarantee that sockets will close in the order they were opened
                continue;
            }
        
            // Send iovec buffer filled with log messages
            retval_ipc = write(sock_args->writeSockets[i], log_iovs[j].iov_base, log_iovs[j].iov_len);
            if (retval_ipc == -1) {
                // Uncomment this next line to enable reusage of old sockets
                // sock_args->socketRecvs[i] = -1
                return IO_IPC_SOCK_CON;
            }
        }
    }

    // The number of logged messages is returned
    return invalid_count;
}

int sock_readv(struct sock_reader_arg_t *sock_args, struct iovec *iovecs) {
    
    int sd, max_sd, newSocket, activity, returnValue;
    fd_set readfds;

    // No messages received yet
    int recv_retval = 0;

    // Clear list of sockets to poll from
    FD_ZERO(&readfds);

    // Adding read socket to list
    FD_SET(sock_args->readSocket, &readfds);

    // Read socket is currently the only socket; therefore the one with the highest socket descriptor
    max_sd = sock_args->readSocket;
    // Add clients
    for (int i = 0; i < MAX_AMOUNT_OF_SOCKETS; i++){
        // To make upcoming code more readable
        sd = sock_args->clientSockets[i];

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
    // We are using select with a timeout to periodically recheck for ctrl+c
    struct timeval tv = {1,0};
    activity = select(max_sd + 1, &readfds, NULL, NULL, &tv);
    if (activity <= 0){
        if (errno == EINTR || activity == 0){
            // We want to close the program with ctrl+c
            return IO_IPC_SUCCESS;
        }

        return IO_IPC_SOCK_CON;
    }

    // New connection is ready to be accepted
    if (FD_ISSET(sock_args->readSocket, &readfds)){
        // fcntl(sock_args->readSocket, F_SETFL, fcntl(sock_args->readSocket, F_GETFL, 0) | O_NONBLOCK);
        newSocket = accept(sock_args->readSocket, (struct sockaddr *)&sock_args->address, (socklen_t*)&sock_args->sizeOfAddressStruct);
        if (errno == EAGAIN){
            return IO_IPC_SUCCESS;
        }
        if (newSocket < 0){
            return IO_IPC_SOCK_CON;
        }

        // Add this connection to array of client sockets
        for (int i = 0; i < MAX_AMOUNT_OF_SOCKETS; i++){
            // Connection must be empty
            if (sock_args->clientSockets[i] == 0){
                sock_args->clientSockets[i] = newSocket;
                break;
            }
        }
    }

    // It may be a different I/O operation
    for (int i = 0; i < MAX_AMOUNT_OF_SOCKETS; i++){
        if (sock_args->clientSockets[i] <= 0){
            continue;
        }
        sd = sock_args->clientSockets[i];

        if (FD_ISSET(sd, &readfds)){
            // Check if it was a close operation
            returnValue = read(sd, iovecs[0].iov_base, 1024);
            if (returnValue > 0){
                recv_retval++;
            }
            if (returnValue == 0){
                // Check who disconnected
                getpeername(sd, (struct sockaddr*)&sock_args->address, (socklen_t*)&sock_args->sizeOfAddressStruct);

                // Close the socket on receiver side
                close(sd);
                sock_args->clientSockets[0] = 0;
            }
        }
    }

    return recv_retval;
}


int sock_finalize(union sock_arg_t *sock_args, int role){
    // There is not a lot to do here, sockets are less complex than shared memory
    return sock_cleanup(sock_args, role);
}

int sock_cleanup(union sock_arg_t *sock_args, int role){
   
    if (role == SOCK_WRITER){

        // Close and unlink all sockets
        for (int i = 0; i < MAX_AMOUNT_OF_SOCKETS; i++){
            close(sock_args->wargs.writeSockets[i]);
            unlink(sock_args->wargs.socketPathNames[i]);
        }

        return IO_IPC_SUCCESS;

    }else{

        // Unlink socket
        close(sock_args->rargs.readSocket);
		unlink(sock_args->rargs.socketPathName);

        return IO_IPC_SUCCESS;
        
    }
}