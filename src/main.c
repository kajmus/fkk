#include <stdio.h>
#include <stdbool.h>
#include "cli/cli.h"
#include "common/event.h"
#include "modes/modes.h"
// #include "modes/guard.h"



int main(int argc, char **argv) {
    struct app_config cfg;

    if (cli_parse(argc, argv, &cfg) != 0) {
        return 1;
    }

    switch (cfg.mode) {
        case MODE_WATCH:
            printf("[START] Tryb WATCH na ścieżce: %s (odświeżanie: %d ms)\n", 
                   cfg.target_path, cfg.refresh_ms);
            // return run_watch_mode(&cfg, &stop_program);
            return mode_watch(&cfg);
            
            // break;

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
