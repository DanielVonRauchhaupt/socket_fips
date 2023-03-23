#ifndef _MSGQ_H
#define _MSGQ_H

#include <zmq.h>



struct msgq_ipc_arg_t 
{
    void * context;
    void * socket;
};




#endif