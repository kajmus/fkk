#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[16];
    char parent_comm[16];
};

/* Ring Buffer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_execve")
int handle_exec(void *ctx)
{
    struct event *e;
    struct task_struct *task;
    struct task_struct *parent;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    task = (struct task_struct *)bpf_get_current_task();
    parent = BPF_CORE_READ(task, real_parent);
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->uid = bpf_get_current_uid_gid();
    bpf_core_read_str(&e->parent_comm, sizeof(e->parent_comm), &parent->comm);

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);

    return 0;
}