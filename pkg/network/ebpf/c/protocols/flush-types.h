#ifndef __USM_FLUSH_TYPES_H
#define __USM_FLUSH_TYPES_H

typedef enum {
    NETIF_PROG_HTTP = 0,
    NETIF_PROG_HTTP2,
    NETIF_PROG_KAFKA,
    NETIF_PROG_POSTGRES,
    NETIF_PROG_REDIS,
    // Add before this value.
    __NETIF_PROG_MAX,
} netif_protocol_prog_t;

#endif
