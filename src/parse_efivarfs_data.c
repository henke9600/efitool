#include "parse_efivarfs_data.h"
#include "argparse.h"
#include "file.h"
#include "util.h"
#include "x.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int parse_efivarfs_data(const char *input_efivarfs_data, const char *output_var_data) {
    int status = -1;
    unsigned char *input_buffer = NULL;
    struct file out;
    file_init(&out);

    size_t input_size;
    if (util_read_full(input_efivarfs_data, &input_buffer, &input_size) < 0) goto err_cleanup;

    if (input_size < 4) goto err_cleanup;
    uint_least32_t attributes = x_load_u32(input_buffer);

    if (file_open(&out, output_var_data, FILE_MODE_WRITE) < 0) goto err_cleanup;
    if (file_write(&out, input_buffer + 4, input_size - 4) < 0) goto err_cleanup;

    if (util_puts_attribute_args(attributes) < 0) goto err_cleanup;
    if (fputs("\n", stdout) == EOF) goto err_cleanup;

    status = 0;

    err_cleanup:
    free(input_buffer);
    if (file_close(&out) < 0) status = -1;
    return status;
}

static int parse_efivarfs_data_usage(FILE *file, const char *parent, const char *const *argv) {
    return fprintf(
        file,
        "Usage: %s %s [OPTION]... EFIVARFS_DATA\n"
        "\n"
        "Options:\n"
        "  -h, --help         Show this help text\n"
        "  -o, --output FILE  Output file\n",
        parent,
        argv[0]
    );
}

int parse_efivarfs_data_main(const char *parent, const char *const *argv) {
    bool help = false;
    const char *output_file = NULL;
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
            if (strcmp(argparse_arg, "-") == 0) goto argparse_done;
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
        return parse_efivarfs_data_usage(stdout, parent, argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    const char *efivarfs_data = argv[argparse_pos++];
    if (efivarfs_data == NULL) {
        (void)fprintf(stderr, "ERROR: Missing EFIVARFS_DATA\n\n");
        goto err_usage;
    }

    if (argv[argparse_pos] != NULL) {
        (void)fprintf(stderr, "ERROR: Too many arguments\n\n");
        goto err_usage;
    }

    return parse_efivarfs_data(efivarfs_data, output_file) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    err_usage:
    parse_efivarfs_data_usage(stderr, parent, argv);
    return EXIT_FAILURE;
}
