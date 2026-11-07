#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "hello.skel.h"

static volatile int running = 1;

struct event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[16];
    char parent_comm[16];
};

static void sig_handler(int signo)
{
    running = 0;
}

static int handle_event(void *ctx, void *data, size_t len)
{
    struct event *e = data;

    printf("PID: %-6d PPID: %-6d UID: %-6d COMM: %s PARENT_COMM: %s\n", e->pid, e->ppid, e->uid, e->comm, e->parent_comm);
    // printf("PID: %-6d PPID: %-6d COMM: %s PARENT_COMM: %s\n", e->pid, e->ppid, e->comm, e->parent_comm);

    return 0;
}

int main(void)
{
    struct hello_bpf *skel;
    struct ring_buffer *rb = NULL;

    signal(SIGINT, sig_handler);

    skel = hello_bpf__open_and_load();
    if (!skel) {
        printf("Load failed\n");
        return 1;
    }

    if (hello_bpf__attach(skel)) {
        printf("Attach failed\n");
        return 1;
    }

    rb = ring_buffer__new(
            bpf_map__fd(skel->maps.events),
            handle_event,
            NULL,
            NULL);

    while (running)
        ring_buffer__poll(rb, 100);

    ring_buffer__free(rb);

    hello_bpf__destroy(skel);

    return 0;
}