#ifndef __TCP_RECV_H
#define __TCP_RECV_H



#include "bpf_helpers.h"
#include "bpf_telemetry.h"
#include "bpf_bypass.h"

#include "tracer/stats.h"
#include "tracer/events.h"
#include "tracer/maps.h"
#include "sock.h"

#if defined(COMPILE_CORE) || defined(COMPILE_RUNTIME)
#define USE_TCP_COPIED_SEQ
#endif

#ifdef USE_TCP_COPIED_SEQ

static __always_inline void initialize_seq(struct sock* skp) {
    u32 copied_seq = BPF_CORE_READ(tcp_sk(skp), copied_seq);
    tcp_state_t state = {
        .copied_seq = copied_seq
    };
    // We skip EEXIST because this is called for every recvmsg and the map is expected
    // to already exist most of the time
    bpf_map_update_with_telemetry(tcp_state, &skp, &state, BPF_NOEXIST, -EEXIST);
}

static __always_inline u32 update_seq(struct sock* skp, tcp_state_t *state) {
    u32 copied_seq = BPF_CORE_READ(tcp_sk(skp), copied_seq);

    u32 old_seq = __sync_lock_test_and_set(&state->copied_seq, copied_seq);

    u32 seq_diff = copied_seq - old_seq;
    return seq_diff;
}

static __always_inline void tcp_recvmsg_use_skp(struct sock* skp) {
    initialize_seq(skp);
}

#else 

static __always_inline void tcp_recvmsg_use_skp(struct sock* skp) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_with_telemetry(tcp_recvmsg_args, &pid_tgid, &skp, BPF_ANY);
}

#endif


SEC("kprobe/tcp_recvmsg")
int BPF_BYPASSABLE_KPROBE(kprobe__tcp_recvmsg) {
#if defined(COMPILE_RUNTIME) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
    struct sock *skp = (struct sock*)PT_REGS_PARM2(ctx);
    int flags = (int)PT_REGS_PARM6(ctx);
#elif defined(COMPILE_RUNTIME) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
    struct sock *skp = (struct sock*)PT_REGS_PARM1(ctx);
    int flags = (int)PT_REGS_PARM5(ctx);
#else
    struct sock *skp = (struct sock*)PT_REGS_PARM1(ctx);
    int flags = (int)PT_REGS_PARM4(ctx);
#endif
    if (flags & MSG_PEEK) {
        return 0;
    }

    tcp_recvmsg_use_skp(skp);
    return 0;
}

#if defined(COMPILE_CORE) || defined(COMPILE_PREBUILT)

SEC("kprobe/tcp_recvmsg")
int BPF_BYPASSABLE_KPROBE(kprobe__tcp_recvmsg__pre_5_19_0) {
    int flags = (int)PT_REGS_PARM5(ctx);
    if (flags & MSG_PEEK) {
        return 0;
    }
    struct sock *skp = (struct sock *)PT_REGS_PARM1(ctx);
    tcp_recvmsg_use_skp(skp);
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_BYPASSABLE_KPROBE(kprobe__tcp_recvmsg__pre_4_1_0) {
    int flags = (int)PT_REGS_PARM6(ctx);
    if (flags & MSG_PEEK) {
        return 0;
    }

    struct sock *skp = (struct sock*)PT_REGS_PARM2(ctx);
    tcp_recvmsg_use_skp(skp);
    return 0;
}

#endif // COMPILE_CORE || COMPILE_PREBUILT

SEC("kretprobe/tcp_recvmsg")
int BPF_BYPASSABLE_KRETPROBE(kretprobe__tcp_recvmsg, int recv) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skpp = (struct sock**) bpf_map_lookup_elem(&tcp_recvmsg_args, &pid_tgid);
    if (!skpp) {
        return 0;
    }

    struct sock *skp = *skpp;
    bpf_map_delete_elem(&tcp_recvmsg_args, &pid_tgid);
    if (!skp) {
        return 0;
    }

    if (recv < 0) {
        return 0;
    }

    return handle_tcp_recv(pid_tgid, skp, recv);
}

SEC("kprobe/tcp_read_sock")
int BPF_BYPASSABLE_KPROBE(kprobe__tcp_read_sock, struct sock *skp) {
#ifdef USE_TCP_COPIED_SEQ
    initialize_seq(skp);
#else
    u64 pid_tgid = bpf_get_current_pid_tgid();
    // we reuse tcp_recvmsg_args here since there is no overlap
    // between the tcp_recvmsg and tcp_read_sock paths
    bpf_map_update_with_telemetry(tcp_recvmsg_args, &pid_tgid, &skp, BPF_ANY);
#endif
    return 0;
}

SEC("kretprobe/tcp_read_sock")
int BPF_BYPASSABLE_KRETPROBE(kretprobe__tcp_read_sock, int recv) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    // we reuse tcp_recvmsg_args here since there is no overlap
    // between the tcp_recvmsg and tcp_read_sock paths
    struct sock **skpp = (struct sock**) bpf_map_lookup_elem(&tcp_recvmsg_args, &pid_tgid);
    if (!skpp) {
        return 0;
    }

    struct sock *skp = *skpp;
    bpf_map_delete_elem(&tcp_recvmsg_args, &pid_tgid);
    if (!skp) {
        return 0;
    }

    if (recv < 0) {
        return 0;
    }

    return handle_tcp_recv(pid_tgid, skp, recv);
}

#ifdef USE_TCP_COPIED_SEQ

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_BYPASSABLE_KPROBE(kprobe__tcp_cleanup_rbuf, struct sock *skp) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    tcp_state_t *state = bpf_map_lookup_elem(&tcp_state, &skp);
    if (!state) {
        return 0;
    }

    u32 seq_diff = update_seq(skp, state);
    const u32 HALF_RANGE = 1 << 31;
    if (seq_diff >= HALF_RANGE) {
        // tcp_cleanup_rbuf is called with the sock lock held, so this should never occur
        log_debug("update_seq saw a decreasing seq number (shouldn't happen): %llu", pid_tgid);
        return 0;
    }

    return handle_tcp_recv(pid_tgid, skp, (int) seq_diff);
}

#endif

#endif // __TCP_RECV_H__
