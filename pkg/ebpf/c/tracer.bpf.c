// +build ignore

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2

char __license[] SEC("license") = "GPL";

struct connect_event {
    __u32 pid;
    __u32 dest_ip;
    __u16 dest_port;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    struct sockaddr_in addr;
    struct connect_event *event;
    
    struct sockaddr *uaddr = (struct sockaddr *)ctx->args[1];
    if (!uaddr)
        return 0;

    bpf_probe_read_user(&addr, sizeof(addr), uaddr);

    if (addr.sin_family != AF_INET)
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->dest_ip = addr.sin_addr.s_addr;
    event->dest_port = bpf_ntohs(addr.sin_port);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}
