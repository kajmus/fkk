#ifndef CLI_H
#define CLI_H

#include <stdbool.h>

typedef enum {
    MODE_NONE = 0,
    MODE_WATCH,
    MODE_GUARD
} app_mode_t;

struct app_config {
    app_mode_t mode;
    const char *target_path; 
    int refresh_ms;
    bool block_writes;
    bool verbose;
};

int cli_parse(int argc, char **argv, struct app_config *cfg);
void cli_print_help(const char *prog_name);

#endif