#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cli.h"

void cli_print_help(const char *prog_name) {
    printf("Użycie: %s <watch|guard> [opcje]\n\n", prog_name);
    printf("Opcje:\n");
    printf("  -p, --path <ścieżka>   Ścieżka do monitorowania/ochrony\n");
    printf("  -i, --interval <ms>    Czas odświeżania dla watch (domyślnie: 1000)\n");
    printf("  -b, --block            Blokuj zapis (tylko dla trybu guard)\n");
    printf("  -v, --verbose          Więcej logów\n");
}

int cli_parse(int argc, char **argv, struct app_config *cfg) {
    // 1. Ustawiamy wartości domyślne
    memset(cfg, 0, sizeof(*cfg));
    cfg->refresh_ms = 1000;
    cfg->target_path = "/";

    if (argc < 2) {
        cli_print_help(argv[0]);
        return -1;
    }

    // 2. Sprawdzamy pierwszy argument (sub-komenda: watch lub guard)
    if (strcmp(argv[1], "watch") == 0) {
        cfg->mode = MODE_WATCH;
    } else if (strcmp(argv[1], "guard") == 0) {
        cfg->mode = MODE_GUARD;
    } else {
        fprintf(stderr, "Błąd: Nieznany tryb '%s'\n", argv[1]);
        cli_print_help(argv[0]);
        return -1;
    }

    // Przesuwamy wskaźniki o 1, żeby getopt_long czytał flagi PO słowie "watch"/"guard"
    argc--;
    argv++;

    // 3. Definiujemy flagi
    static struct option long_options[] = {
        {"path",     required_argument, 0, 'p'},
        {"interval", required_argument, 0, 'i'},
        {"block",    no_argument,       0, 'b'},
        {"verbose",  no_argument,       0, 'v'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:i:bv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                cfg->target_path = optarg;
                break;
            case 'i':
                cfg->refresh_ms = atoi(optarg);
                break;
            case 'b':
                cfg->block_writes = true;
                break;
            case 'v':
                cfg->verbose = true;
                break;
            default:
                return -1;
        }
    }

    return 0;
}