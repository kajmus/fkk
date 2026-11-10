#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include "cli/cli.h"
#include "common/event.h"
#include "modes/modes.h"
#include "modes/watch.c"
// #include "modes/guard.h"

volatile sig_atomic_t stop_program = 0;

static void sig_handler(int signo) {
    printf("\n[INFO] signal recived %d\n", signo);
    stop_program = 1;
}

static int handle_event(void *ctx, void *data, size_t data_s){
    struct event *e = data;
    printf(

    );
    return 0;
}

int main(int argc, char **argv) {
    struct app_config cfg;

    if (cli_parse(argc, argv, &cfg) != 0) {
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    switch (cfg.mode) {
        case MODE_WATCH:
            printf("[START] Tryb WATCH na ścieżce: %s (odświeżanie: %d ms)\n", 
                   cfg.target_path, cfg.refresh_ms);
            // return run_watch_mode(&cfg, &stop_program);
            
            break;

        case MODE_GUARD:
            printf("[START] Tryb GUARD na ścieżce: %s (blokowanie: %s)\n", 
                   cfg.target_path, cfg.block_writes ? "TAK" : "NIE");
            // return run_guard_mode(&cfg, &stop_program);
            break;

        default:
            return 1;
    }

    return 0;
}