// #define _POSIX_C_SOURCE 199309L
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include <bpf/libbpf.h>
#include "../bpf/watch.skel.h"

#include "../modes/modes.h"
#include "../common/event.h"

#define DROP_CHECK_INTERVAL_NS (1000000000ULL) // 1 second
static volatile sig_atomic_t stop_program = 0;


static void sig_handler(int signo) {
    // printf("\n[INFO] signal recived %d\n", signo);
	(void)signo;
    stop_program = 1;
}

static uint64_t now_monotonic_ns(void){
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * DROP_CHECK_INTERVAL_NS + (uint64_t)ts.tv_nsec;
}

static const char *op_to_str(uint32_t op){
	switch (op){
		case FKK_OP_OPEN_READ: return "open_read";
    	case FKK_OP_OPEN_WRITE: return "open_write";
    	case FKK_OP_OPEN_RDWR: return "open_rdwr";
    	case FKK_OP_CREATE: return "create";
    	case FKK_OP_UNLINK: return "unlink";
    	case FKK_OP_RENAME: return "rename";
    	case FKK_OP_CHMOD: return "chmod";
    	case FKK_OP_CHOWN: return "chown";
		default: return "other";
	}
}
struct watch_ctx {
	const struct bpf_map *drops_map;
	int num_cpus;
	uint64_t *percpu_buf;
	size_t percpu_buf_sz;
	uint64_t prev_drops[FKK_OP_MAX];
	uint64_t total_drops_seen;
	uint64_t last_check_ns;
	uint64_t events_in_batch;
};

static int drop_tracker_init(struct watch_ctx *ctx, const struct bpf_map *drops_map){
    if (!drops_map) return -1;

	int n = libbpf_num_possible_cpus();
    if (n <= 0) {
        fprintf(stderr, "[ERROR] libbpf_num_possible_cpus failed: %d\n", n);
        return -1;
    }

    ctx->percpu_buf = calloc((size_t)n, sizeof(uint64_t));
    if (!ctx->percpu_buf) {
        perror("calloc percpu_buf");
        return -1;
    }

    ctx->drops_map = drops_map;
    ctx->num_cpus = n;
    ctx->percpu_buf_sz = (size_t)n * sizeof(uint64_t);
    ctx->last_check_ns = now_monotonic_ns();
    return 0;
}

static void drop_tracker_free(struct watch_ctx *ctx){
    free(ctx->percpu_buf);
    ctx->percpu_buf = NULL;
}

static void check_drops(struct watch_ctx *ctx, bool force){
	// force is for exiting
    if (!ctx->drops_map || !ctx->percpu_buf)
        return;

    uint64_t now = now_monotonic_ns();
    if (!force && (now - ctx->last_check_ns) < DROP_CHECK_INTERVAL_NS)
        return;

    double elapsed_s = (double)(now - ctx->last_check_ns) / 1e9;
    ctx->last_check_ns = now;

    uint64_t deltas[FKK_OP_MAX] = { 0 };
    uint64_t delta_total = 0;

    for (uint32_t op = 0; op < FKK_OP_MAX; op++) {
        int err = bpf_map__lookup_elem(
            ctx->drops_map,
            &op, sizeof(op),
            ctx->percpu_buf, ctx->percpu_buf_sz,
            0);
        if (err != 0) continue;

        uint64_t current_sum = 0;
        for (int cpu = 0; cpu < ctx->num_cpus; cpu++)
            current_sum += ctx->percpu_buf[cpu];

        uint64_t delta = current_sum - ctx->prev_drops[op];
        ctx->prev_drops[op] = current_sum;

        deltas[op] = delta;
        delta_total += delta;
    }

    if (delta_total > 0) {
        ctx->total_drops_seen += delta_total;

        fprintf(stderr,
                "[TELEMETRY_WARNING] dropped %llu events in last %.2fs "
                "(total since start: %llu) | breakdown:",
                (unsigned long long)delta_total,
                elapsed_s,
                (unsigned long long)ctx->total_drops_seen);

        for (uint32_t op = 0; op < FKK_OP_MAX; op++) {
            if (deltas[op] > 0) {
                fprintf(stderr, " %s=%llu",
                        op_to_str(op),
                        (unsigned long long)deltas[op]);
            }
        }
        fprintf(stderr, "\n");
    }
}

static int handle_event(void *raw_ctx, void *data, size_t data_s){
    (void)data_s;
	struct watch_ctx *ctx = raw_ctx;
	struct event *e = data;

	if(stop_program) return -EINTR;

    printf("[EVENT] type=%u op=%s pid=%u ppid=%u comm=%s path=%s flags=0x%x\n",
           e->type, op_to_str(e->file.op), e->pid, e->ppid,
           e->comm, e->file.path, e->flags);
    if ((++ctx->events_in_batch & 1023ULL) == 0)
        check_drops(ctx, false);

    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	// if (level == LIBBPF_DEBUG && !env.verbose)
	// 	return 0;
	return vfprintf(stderr, format, args);
}

int mode_watch(struct app_config *cfg){
    struct watch_bpf *skel;
    struct ring_buffer *rb = NULL;
	struct watch_ctx ctx = {0};
	int err = 0;
    // debugging
	// libbpf_set_print(libbpf_print_fn);
	
	(void)cfg;
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);


    skel = watch_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->self_tgid = (uint32_t)getpid();

    err = watch_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	if (drop_tracker_init(&ctx, skel->maps.drops) != 0) {
	        err = -1;
	        goto cleanup;
	    }

    err = watch_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, &ctx, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}


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
		check_drops(&ctx, false);
	}

	check_drops(&ctx, true);
	fprintf(stderr, "[INFO] Stopping. Total dropped events: %llu\n",
            (unsigned long long)ctx.total_drops_seen);

cleanup:
	ring_buffer__free(rb);
	drop_tracker_free( &ctx);
	watch_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}