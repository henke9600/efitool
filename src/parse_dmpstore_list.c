#include "parse_dmpstore_list.h"
#include "argparse.h"
#include "efi.h"
#include "file.h"
#include "util.h"
#include "x.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define OUT_NAME_FMT "%s%zu%s"
#define CONSTANT_SIZE (4 + 4 + EFI_GUID_SIZE + 4 + 4)
static int parse_dmpstore_list(char *input_ds_list, char *output_prefix, char *output_suffix) {
    int status = -1;
    unsigned char *input_buffer = NULL;

    size_t input_size;
    if (util_read_full(input_ds_list, &input_buffer, &input_size) < 0) goto err_cleanup;

    size_t off = 0;
    for (size_t n = 1; off < input_size; ++n) {
        bool inner_error = true;
        struct file out;
        file_init(&out);
        char *out_name = NULL;

        if (off > input_size - CONSTANT_SIZE) goto inner_err_cleanup;
        uint_least32_t var_name_ucs2_size = x_load_u32(input_buffer + off);
        uint_least32_t data_size = x_load_u32(input_buffer + off + 4);

        size_t variable_remaining = input_size - (off + CONSTANT_SIZE);
        if (
            var_name_ucs2_size > variable_remaining ||
            data_size > (variable_remaining - var_name_ucs2_size)
        ) goto inner_err_cleanup;

        if (output_prefix != NULL) {
            int out_name_len = snprintf(NULL, 0, OUT_NAME_FMT, output_prefix, n, output_suffix);
            if (out_name_len < 0) goto inner_err_cleanup;
            size_t out_name_size = (size_t)out_name_len + 1;
            out_name = malloc(out_name_size);
            if (out_name == NULL) goto inner_err_cleanup;
            if (snprintf(
                out_name, out_name_size,
                OUT_NAME_FMT, output_prefix, n, output_suffix
            ) < 0) goto inner_err_cleanup;
        }

        size_t entry_size = CONSTANT_SIZE + var_name_ucs2_size + data_size;
        if (file_open(&out, out_name, FILE_MODE_WRITE) < 0) goto inner_err_cleanup;
        if (file_write(&out, input_buffer + off, entry_size) < 0) goto inner_err_cleanup;
        off += entry_size;

        inner_error = false;

        inner_err_cleanup:
        if (file_close(&out) < 0) inner_error = true;
        free(out_name);
        if (inner_error) goto err_cleanup;
    }

    status = 0;

    err_cleanup:
    free(input_buffer);
    return status;
}
#undef OUT_NAME_FMT
#undef CONSTANT_SIZE

static int parse_dmpstore_list_usage(FILE *file, char *parent, char **argv) {
    return fprintf(
        file,
        "Usage: %s %s [OPTION]... DMPSTORE_LIST\n"
        "\n"
        "Options:\n"
        "  -h, --help                  Show this help text\n"
        "  -o, --output-prefix PREFIX  Output file prefix\n"
        "  -s, --suffix SUFFIX         Output file suffix. Defaults to .dsd\n",
        parent,
        argv[0]
    );
}

int parse_dmpstore_list_main(char *parent, char **argv) {
    bool help = false;
    char *output_prefix = NULL;
    char *suffix = ".dsd";
    ARGPARSE_BEGIN(argv)
        if (strcmp(argparse_long_opt, "help") == 0)          { argparse_arg = "h"; break; }
        if (strcmp(argparse_long_opt, "output-prefix") == 0) { argparse_arg = "o"; break; }
        if (strcmp(argparse_long_opt, "suffix") == 0)        { argparse_arg = "s"; break; }
    ARGPARSE_LONG_OPTS_TO_FLAGS_DELIMITER
        case 'h': {
            help = true;
            break;
        }
    ARGPARSE_FLAGS_TO_ARGS_DELIMITER
        case 'o': {
            output_prefix = argparse_arg;
            break;
        }
        case 's': {
            suffix = argparse_arg;
            break;
        }
    ARGPARSE_END

    if (argparse_opt != '\0') {
        if (argparse_long_opt != NULL) (void)fprintf(stderr, "ERROR: Invalid long option '%s'\n\n", argparse_long_opt);
        else                           (void)fprintf(stderr, "ERROR: Invalid option '%c'\n\n", argparse_opt);
        goto err_usage;
    }

    if (help) {
        return parse_dmpstore_list_usage(stdout, parent, argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    char *dmpstore_list = argv[argparse_pos++];
    if (dmpstore_list == NULL) {
        (void)fprintf(stderr, "ERROR: Missing DMPSTORE_LIST\n\n");
        goto err_usage;
    }

    if (argv[argparse_pos] != NULL) {
        (void)fprintf(stderr, "ERROR: Too many arguments\n\n");
        goto err_usage;
    }

    return parse_dmpstore_list(dmpstore_list, output_prefix, suffix) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    err_usage:
    parse_dmpstore_list_usage(stderr, parent, argv);
    return EXIT_FAILURE;
}
