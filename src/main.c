#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include "cli/cli.h"
// #include "modes/watch.h"
// #include "modes/guard.h"

// Globalna flaga dla pętli eBPF - gdy użytkownik wciśnie Ctrl+C, zmieni się na true
volatile sig_atomic_t stop_program = 0;

static void sig_handler(int signo) {
    stop_program = 1;
}

int main(int argc, char **argv) {
    struct app_config cfg;

    // 1. Przetwórz argumenty na strukturę
    if (cli_parse(argc, argv, &cfg) != 0) {
        return 1;
    }

    // 2. Złap Ctrl+C (SIGINT) i SIGTERM - kluczowe w eBPF, by posprzątać po sobie!
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 3. Odpal odpowiedni moduł przekazujać wskaźnik do konfiguracji
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