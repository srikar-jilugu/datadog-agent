#ifndef __EXAMPLE_TYPES_H
#define __EXAMPLE_TYPES_H

typedef struct {
    char buf[208];
    char comm_name[16];
    __u64 pid;
    __u8 buf_len;
} message_t;

#endif
