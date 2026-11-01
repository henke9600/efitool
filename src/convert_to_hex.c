#include "convert_to_hex.h"
#include "argparse.h"
#include "file.h"
#include "util.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int convert_to_hex(bool lowercase, bool no_newline, const char *input, const char *output_hex) {
    int status = -1;
    unsigned char *input_buffer = NULL;
    char *hex_buffer = NULL;
    struct file out;
    file_init(&out);

    size_t input_size;
    if (util_read_full(input, &input_buffer, &input_size) < 0) goto err_cleanup;

    size_t hex_buffer_len = input_size * 2 + !no_newline;
    if (hex_buffer_len > SIZE_MAX - 1) goto err_cleanup;
    hex_buffer = malloc(hex_buffer_len + 1);
    if (hex_buffer == NULL) goto err_cleanup;

    if (file_open(&out, output_hex, FILE_MODE_WRITE | FILE_MODE_TEXT) < 0) goto err_cleanup;

    const char *hex_table = lowercase ? "0123456789abcdef" : "0123456789ABCDEF";
    for (size_t i = 0; i < input_size; ++i) {
        size_t hex_i = i * 2;
        unsigned char byte = input_buffer[i];
        hex_buffer[hex_i] = hex_table[byte >> 4];
        hex_buffer[hex_i + 1] = hex_table[byte & 0xF];
    }

    if (!no_newline) hex_buffer[hex_buffer_len - 1] = '\n';
    hex_buffer[hex_buffer_len] = '\0';

    if (file_puts(&out, hex_buffer) < 0) goto err_cleanup;

    status = 0;

    err_cleanup:
    free(input_buffer);
    free(hex_buffer);
    if (file_close(&out) < 0) status = -1;
    return status;
}

static int convert_to_hex_usage(FILE *file, const char *parent, const char *const *argv) {
    return fprintf(
        file,
        "Usage: %s %s [OPTION]... DATA\n"
        "\n"
        "Options:\n"
        "  -h, --help         Show this help text\n"
        "  -o, --output FILE  Output file. Defaults to stdout\n"
        "  -n, --no-newline   Omit trailing newline in output\n"
        "  -l, --lowercase    Output in lowercase\n",
        parent,
        argv[0]
    );
}

int convert_to_hex_main(const char *parent, const char *const *argv) {
    bool help = false;
    const char *output_file = "-";
    bool no_newline = false;
    bool lowercase = false;
    ARGPARSE_BEGIN(argv)
        if (strcmp(argparse_long_opt, "help") == 0)       { argparse_arg = "h"; break; }
        if (strcmp(argparse_long_opt, "output") == 0)     { argparse_arg = "o"; break; }
        if (strcmp(argparse_long_opt, "no-newline") == 0) { argparse_arg = "n"; break; }
        if (strcmp(argparse_long_opt, "lowercase") == 0)  { argparse_arg = "l"; break; }
    ARGPARSE_LONG_OPTS_TO_FLAGS_DELIMITER
        case 'h': {
            help = true;
            break;
        }
        case 'n': {
            no_newline = true;
            break;
        }
        case 'l': {
            lowercase = true;
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
        return convert_to_hex_usage(stdout, parent, argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    const char *data = argv[argparse_pos++];
    if (data == NULL) {
        (void)fprintf(stderr, "ERROR: Missing DATA\n\n");
        goto err_usage;
    }

    if (argv[argparse_pos] != NULL) {
        (void)fprintf(stderr, "ERROR: Too many arguments\n\n");
        goto err_usage;
    }

    return convert_to_hex(lowercase, no_newline, data, output_file) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    err_usage:
    convert_to_hex_usage(stderr, parent, argv);
    return EXIT_FAILURE;
}
