#ifndef __USM_FLUSH_H
#define __USM_FLUSH_H

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_bypass.h"

#include "protocols/http/http.h"
#include "protocols/http2/decoding.h"
#include "protocols/kafka/kafka-parsing.h"
#include "protocols/postgres/decoding.h"
#include "protocols/redis/decoding.h"
#include "protocols/flush-types.h"

BPF_PROG_ARRAY(netif_dispatcher_progs, __NETIF_PROG_MAX);
BPF_HASH_MAP(netif_dispacther_mapping, netif_protocol_prog_t, netif_protocol_prog_t, __NETIF_PROG_MAX);

static __always_inline void dynamic_tail_call(void *ctx, __u32 current_prog_idx) {
    log_debug("heyyyyyy\n");
    netif_protocol_prog_t *next_prog_idx = bpf_map_lookup_elem(&netif_dispacther_mapping, &current_prog_idx);
    if (next_prog_idx) {
        bpf_tail_call_compat(ctx, &netif_dispatcher_progs, *next_prog_idx);
    }
}

SEC("tracepoint/net/netif_receive_skb")
int tracepoint__net__netif_receive_skb(void *ctx) {
    log_debug("guy base\n");
    return 0;
}

SEC("tracepoint/net/netif_receive_skb")
int tracepoint__net__netif_receive_skb_http(void *ctx) {
    http_batch_flush_with_telemetry(ctx);
    log_debug("tracepoint__net__netif_receive_skb_http\n");
    dynamic_tail_call(ctx, NETIF_PROG_HTTP);
    return 0;
}

SEC("tracepoint/net/netif_receive_skb")
int tracepoint__net__netif_receive_skb_http2(void *ctx) {
    http2_batch_flush_with_telemetry(ctx);
    log_debug("tracepoint__net__netif_receive_skb_http2\n");
    terminated_http2_batch_flush_with_telemetry(ctx);
    dynamic_tail_call(ctx, NETIF_PROG_HTTP2);
    return 0;
}

SEC("tracepoint/net/netif_receive_skb")
int tracepoint__net__netif_receive_skb_kafka(void *ctx) {
    kafka_batch_flush_with_telemetry(ctx);
    log_debug("tracepoint__net__netif_receive_skb_kafka\n");
    dynamic_tail_call(ctx, NETIF_PROG_KAFKA);
    return 0;
}

SEC("tracepoint/net/netif_receive_skb")
int tracepoint__net__netif_receive_skb_postgres(void *ctx) {
    postgres_batch_flush_with_telemetry(ctx);
    log_debug("tracepoint__net__netif_receive_skb_postgres\n");
    dynamic_tail_call(ctx, NETIF_PROG_POSTGRES);
    return 0;
}

SEC("tracepoint/net/netif_receive_skb")
int tracepoint__net__netif_receive_skb_redis(void *ctx) {
    redis_batch_flush_with_telemetry(ctx);
    log_debug("tracepoint__net__netif_receive_skb_redis\n");
    dynamic_tail_call(ctx, NETIF_PROG_REDIS);
    return 0;
}

#endif
