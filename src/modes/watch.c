#include <stdio.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "../bpf/watch.skel.h"

#include "../modes/modes.h"
#include "../common/event.h"

// volatile sig_atomic_t stop_program = 0;
static volatile bool stop_program = false;


static void sig_handler(int signo) {
    printf("\n[INFO] signal recived %d\n", signo);
    stop_program = 1;
}

static int handle_event(void *ctx, void *data, size_t data_s){
    struct event *e = data;
	printf("[EVENT] type=%d pid=%d ppid=%d comm=%s path=%s flags=0x%x\n",
		e->type, e->pid, e->ppid, e->comm, e->file.path, e->flags);
    return 0;
}

int mode_watch(struct app_config *cfg){
    struct watch_bpf *skel;
    struct ring_buffer *rb = NULL;
	int err;
    // rn optional i think
	// libbpf_set_print(libbpf_print_fn);

    // struct app_config temp = *cfg;

    printf("jpd: %s", cfg->target_path);



    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);


    skel = watch_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	// skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

    err = watch_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    err = watch_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

    printf("%-8s %-5s %-16s %-7s %-7s %s\n", 
		"TYPE", "PID", "PPID", "COMM", "PATH", "FLAGS");
	while (!stop_program) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR){
			err =0;
			break;
		}
		if (err <0){
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}
cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	watch_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}