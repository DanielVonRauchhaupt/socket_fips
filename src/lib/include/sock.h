#ifdef _SOCK_IPC_H
#define _SOCK_IPC_H

#include <sys/socket.h>
#include 

struct sock_arg_t 
{
    in_port_t port;
    int socket_fd;
}

int init_socket(struct sock_arg_t * sock_arg);

int close_socket(struct sock_arg_t * sock_arg);

#endif