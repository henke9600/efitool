#include "convert_from_hex.h"
#include "argparse.h"
#include "file.h"
#include "util.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int convert_from_hex(char *input_hex, char *output) {
    int status = -1;
    char *input_buffer = NULL;
    unsigned char *output_buffer = NULL;
    struct file out;
    file_init(&out);

    size_t input_len;
    if (util_read_full_string(input_hex, &input_buffer, &input_len) < 0) goto err_cleanup;

    // Permit a trailing newline
    if (input_len > 0 && input_buffer[input_len - 1] == '\n') --input_len;

    if (input_len % 2 != 0) {
        (void)fprintf(stderr, "ERROR: Input size must be an even number of characters\n");
        goto err_cleanup;
    }

    size_t output_size = input_len / 2;
    output_buffer = NULL;
    if (output_size > 0) {
        output_buffer = malloc(output_size);
        if (output_buffer == NULL) goto err_cleanup;
    }

    for (size_t i = 0; i < output_size; ++i) {
        size_t hex_i = i * 2;

        uint_least32_t byte = 0;
        if (util_parse_hex(input_buffer + hex_i, 2, &byte) != 2) {
            (void)fprintf(stderr, "ERROR: Input contains invalid hex characters\n");
            goto err_cleanup;
        }
        output_buffer[i] = (unsigned char)byte;
    }

    if (file_open(&out, output, FILE_MODE_WRITE) < 0) goto err_cleanup;
    if (file_write(&out, output_buffer, output_size) < 0) goto err_cleanup;

    status = 0;

    err_cleanup:
    free(input_buffer);
    free(output_buffer);
    if (file_close(&out) < 0) status = -1;
    return status;
}

static int convert_from_hex_usage(FILE *file, char *parent, char **argv) {
    return fprintf(
        file,
        "Usage: %s %s [OPTION]... HEX_DATA\n"
        "\n"
        "Options:\n"
        "  -h, --help         Show this help text\n"
        "  -o, --output FILE  Output file. Defaults to stdout\n",
        parent,
        argv[0]
    );
}

int convert_from_hex_main(char *parent, char **argv) {
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
        return convert_from_hex_usage(stdout, parent, argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    char *hex_data = argv[argparse_pos++];
    if (hex_data == NULL) {
        (void)fprintf(stderr, "ERROR: Missing HEX_DATA\n\n");
        goto err_usage;
    }

    if (argv[argparse_pos] != NULL) {
        (void)fprintf(stderr, "ERROR: Too many arguments\n\n");
        goto err_usage;
    }

    return convert_from_hex(hex_data, output_file) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    err_usage:
    convert_from_hex_usage(stderr, parent, argv);
    return EXIT_FAILURE;
}
