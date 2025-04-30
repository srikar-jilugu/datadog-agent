#ifndef __EXAMPLE_H
#define __EXAMPLE_H

#include "protocols/events.h"
#include "types.h"

// This controls the number of Kafka transactions read from userspace at a time
#define EXAMPLE_BATCH_SIZE (MAX_BATCH_SIZE(message_t))

USM_EVENTS_INIT(example, message_t, EXAMPLE_BATCH_SIZE);

struct trace_entry2 {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_event_raw_sys_enter2 {
	struct trace_entry2 ent;
	long int id;
	long unsigned int args[6];
	char __data[0];
};

struct trace_event_raw_sys_exit2 {
	struct trace_entry2 ent;
	long int id;
	long int ret;
	char __data[0];
};

BPF_PERCPU_ARRAY_MAP(message_heap, message_t, 1)

BPF_HASH_MAP(example_map, u64, char *, 1)

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__sys_enter_read(struct trace_event_raw_sys_enter2 *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (ctx->args[1] == 0) {
        return 0;
    }
    char *buf = (char*)ctx->args[1];
    bpf_map_update_elem(&example_map, &pid_tgid, &buf, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint__sys_exit_read(struct trace_event_raw_sys_exit2 *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    ssize_t bytes_count = ctx->ret;
    if (bytes_count < 0) {
        return 0;
    }

    char *buf = (char*)bpf_map_lookup_elem(&example_map, &pid_tgid);
    if (buf == NULL) {
        return 0;
    }


    const u32 key = 0;
    message_t *output = bpf_map_lookup_elem(&message_heap, &key);
    if (output == NULL) {
        return 0;
    }
    output->pid = GET_USER_MODE_PID(pid_tgid);
    if (bytes_count > 128) {
//        bpf_probe_read_user(&output, 128, buf);
        output->buf_len = 128;
    } else if (bytes_count > 0) {
//        bpf_probe_read_user(&output, bytes_count, buf);
        output->buf_len = bytes_count;
    }

    bpf_map_delete_elem(&example_map, &pid_tgid);

    bpf_get_current_comm(&output->comm_name, sizeof(output->comm_name));

    bpf_printk("hello guy3");
    example_batch_enqueue(output);
    example_batch_enqueue(output);
    example_batch_enqueue(output);
    example_batch_enqueue(output);
    example_batch_enqueue(output);
    example_batch_enqueue(output);
    example_batch_enqueue(output);
    example_batch_enqueue(output);
    example_batch_enqueue(output);
    example_batch_enqueue(output);
    example_batch_flush((void*)ctx);

    return 0;
}

#endif
