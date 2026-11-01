#include "parse_signature_database.h"
#include "argparse.h"
#include "efi.h"
#include "file.h"
#include "util.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define OUT_NAME_FMT "%s%zu%s"
static int parse_signature_database(const char *input_db, const char *output_prefix, const char *output_suffix) {
    int status = -1;
    unsigned char *input_buffer = NULL;

    size_t input_size;
    if (util_read_full(input_db, &input_buffer, &input_size) < 0) goto err_cleanup;

    size_t off = 0;
    for (size_t n = 1; off < input_size; ++n) {
        bool inner_error = true;
        struct file out;
        file_init(&out);
        char *out_name = NULL;

        if (input_size - off < EFI_SIGNATURE_LIST_SIZE) goto inner_err_cleanup;
        struct efi_signature_list efi_sig_list;
        efi_signature_list_read(&efi_sig_list, input_buffer + off);
        if (
            efi_sig_list.signature_list_size < EFI_SIGNATURE_LIST_SIZE ||
            efi_sig_list.signature_list_size > input_size - off
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

        if (file_open(&out, out_name, FILE_MODE_WRITE) < 0) goto inner_err_cleanup;
        if (file_write(&out, input_buffer + off, efi_sig_list.signature_list_size) < 0) goto inner_err_cleanup;
        off += efi_sig_list.signature_list_size;

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

static int parse_signature_database_usage(FILE *file, const char *parent, const char *const *argv) {
    return fprintf(
        file,
        "Usage: %s %s [OPTION]... SIGNATURE_DATABASE\n"
        "\n"
        "Options:\n"
        "  -h, --help                  Show this help text\n"
        "  -o, --output-prefix PREFIX  Output file prefix\n"
        "  -s, --suffix SUFFIX         Output file suffix. Defaults to .esl\n",
        parent,
        argv[0]
    );
}

int parse_signature_database_main(const char *parent, const char *const *argv) {
    bool help = false;
    const char *output_prefix = NULL;
    const char *suffix = ".esl";
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
        return parse_signature_database_usage(stdout, parent, argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    const char *signature_database = argv[argparse_pos++];
    if (signature_database == NULL) {
        (void)fprintf(stderr, "ERROR: Missing SIGNATURE_DATABASE\n\n");
        goto err_usage;
    }

    if (argv[argparse_pos] != NULL) {
        (void)fprintf(stderr, "ERROR: Too many arguments\n\n");
        goto err_usage;
    }

    return parse_signature_database(signature_database, output_prefix, suffix) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    err_usage:
    parse_signature_database_usage(stderr, parent, argv);
    return EXIT_FAILURE;
}
