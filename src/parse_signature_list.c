#include "parse_signature_list.h"
#include "argparse.h"
#include "efi.h"
#include "file.h"
#include "util.h"

#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define OUT_NAME_FMT "%s%zu%s"
static int parse_signature_list(char *input_esl, char *output_prefix, char *output_suffix) {
    int status = -1;
    unsigned char *input_buffer = NULL;

    size_t input_size;
    if (util_read_full(input_esl, &input_buffer, &input_size) < 0) goto err_cleanup;

    if (input_size < EFI_SIGNATURE_LIST_SIZE) goto err_cleanup;
    struct efi_signature_list efi_sig_list;
    efi_signature_list_read(&efi_sig_list, input_buffer);

    if (
        efi_sig_list.signature_list_size != input_size ||
        efi_sig_list.signature_header_size != 0 ||
        efi_sig_list.signature_size < EFI_SIGNATURE_DATA_SIZE ||
        (input_size - EFI_SIGNATURE_LIST_SIZE) % efi_sig_list.signature_size != 0
    ) goto err_cleanup;

    size_t off = EFI_SIGNATURE_LIST_SIZE;
    for (size_t n = 1; off < input_size; ++n) {
        bool inner_error = true;
        struct file out;
        file_init(&out);
        char *out_name = NULL;

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
        if (file_write(&out, input_buffer + off, efi_sig_list.signature_size) < 0) goto inner_err_cleanup;
        off += efi_sig_list.signature_size;

        inner_error = false;

        inner_err_cleanup:
        if (file_close(&out) < 0) inner_error = true;
        free(out_name);
        if (inner_error) goto err_cleanup;
    }

    // Write parsed header to stdout
    char type_guid[UTIL_PRINT_GUID_BUFFER_SIZE];
    util_print_guid(&efi_sig_list.signature_type, &type_guid[0]);
    if (fprintf(
        stdout,
        "%s\t%" PRIuLEAST32 "\t%" PRIuLEAST32 "\n",
        &type_guid[0],
        efi_sig_list.signature_list_size,
        efi_sig_list.signature_size
    ) < 0) goto err_cleanup;

    status = 0;

    err_cleanup:
    free(input_buffer);
    return status;
}
#undef OUT_NAME_FMT

static int parse_signature_list_usage(FILE *file, char *parent, char **argv) {
    return fprintf(
        file,
        "Usage: %s %s [OPTION]... SIGNATURE_LIST\n"
        "\n"
        "Options:\n"
        "  -h, --help                  Show this help text\n"
        "  -o, --output-prefix PREFIX  Output file prefix\n"
        "  -s, --suffix SUFFIX         Output file suffix. Defaults to .esd\n",
        parent,
        argv[0]
    );
}

int parse_signature_list_main(char *parent, char **argv) {
    bool help = false;
    char *output_prefix = NULL;
    char *suffix = ".esd";
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
        return parse_signature_list_usage(stdout, parent, argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    char *input_esl = argv[argparse_pos++];
    if (input_esl == NULL) {
        (void)fprintf(stderr, "ERROR: Missing SIGNATURE_LIST\n\n");
        goto err_usage;
    }

    if (argv[argparse_pos] != NULL) {
        (void)fprintf(stderr, "ERROR: Too many arguments\n\n");
        goto err_usage;
    }

    return parse_signature_list(input_esl, output_prefix, suffix) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    err_usage:
    parse_signature_list_usage(stderr, parent, argv);
    return EXIT_FAILURE;
}
