#pragma once

struct user_msghdr {
    void *msg_name;           
    int msg_namelen;          
    struct iovec *msg_iov;    
    __kernel_size_t msg_iovlen;
    void *msg_control;         
    __kernel_size_t msg_controllen;
    unsigned int msg_flags;    
};
