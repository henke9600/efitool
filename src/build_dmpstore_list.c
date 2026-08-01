#include "build_dmpstore_list.h"
#include "argparse.h"
#include "util.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int build_dmpstore_list_usage(FILE *file, char *parent, char **argv) {
    return fprintf(
        file,
        "Usage: %s %s [OPTION]... DMPSTORE_DATA...\n"
        "\n"
        "Options:\n"
        "  -h, --help         Show this help text\n"
        "  -o, --output FILE  Output file. Defaults to stdout\n",
        parent,
        argv[0]
    );
}

int build_dmpstore_list_main(char *parent, char **argv) {
    bool help = false;
    char *output_file = "-";
    ARGPARSE_BEGIN(argv)
        if (strcmp(argparse_long_opt, "help") == 0)   { argparse_arg = "h"; break; }
        if (strcmp(argparse_long_opt, "output") == 0) { argparse_arg = "o"; break; }
    ARGPARSE_LONG_OPTS_TO_FLAGS_DELIMITER
        case 'h': {
            help = true;
            break;
        }
    ARGPARSE_FLAGS_TO_ARGS_DELIMITER
        case 'o': {
            output_file = argparse_arg;
            break;
        }
    ARGPARSE_END

    if (argparse_opt != '\0') {
        if (argparse_long_opt != NULL) (void)fprintf(stderr, "ERROR: Invalid long option '%s'\n\n", argparse_long_opt);
        else                           (void)fprintf(stderr, "ERROR: Invalid option '%c'\n\n", argparse_opt);
        goto err_usage;
    }

    if (help) {
        return build_dmpstore_list_usage(stdout, parent, argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    if (argv[argparse_pos] == NULL) {
        (void)fprintf(stderr, "ERROR: Missing DMPSTORE_DATA\n\n");
        goto err_usage;
    }

    return util_concatenate(argv + argparse_pos, output_file) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    err_usage:
    build_dmpstore_list_usage(stderr, parent, argv);
    return EXIT_FAILURE;
}
