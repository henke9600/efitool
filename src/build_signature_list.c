#include "build_signature_list.h"
#include "argparse.h"
#include "efi.h"
#include "file.h"
#include "util.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int build_signature_list(
    const struct efi_guid *signature_type,
    const char *const *input_sig_datas,
    size_t input_sig_datas_len,
    const char *output_esl
) {
    int status = -1;
    struct file out;
    file_init(&out);

    uint_least32_t signature_data_size;
    for (size_t i = 0; i < input_sig_datas_len; ++i) {
        bool inner_error = true;
        unsigned char *file_buffer = NULL;

        size_t file_size;
        if (util_read_full(input_sig_datas[i], &file_buffer, &file_size) < 0) goto inner_err_cleanup;

        if (i == 0) {
            if (
                file_size == 0 ||
                input_sig_datas_len > (0xFFFFFFFF - EFI_SIGNATURE_LIST_SIZE) / file_size
            ) goto inner_err_cleanup;

            signature_data_size = (uint_least32_t)file_size;
            uint_least32_t signature_datas_size = (uint_least32_t)input_sig_datas_len * signature_data_size;

            if (file_open(&out, output_esl, FILE_MODE_WRITE) < 0) goto inner_err_cleanup;

            struct efi_signature_list efi_sig_list;
            memcpy(&efi_sig_list.signature_type, signature_type, sizeof(*signature_type));
            efi_sig_list.signature_list_size = EFI_SIGNATURE_LIST_SIZE + signature_datas_size;
            efi_sig_list.signature_header_size = 0;
            efi_sig_list.signature_size = signature_data_size;

            unsigned char bytes[EFI_SIGNATURE_LIST_SIZE];
            efi_signature_list_write(&efi_sig_list, &bytes[0]);
            if (file_write(&out, &bytes[0], sizeof(bytes)) < 0) goto inner_err_cleanup;
        } else if (file_size != signature_data_size) {
            (void)fprintf(stderr, "ERROR: Every signature data must be of the same size\n");
            goto inner_err_cleanup;
        }

        if (file_write(&out, file_buffer, file_size) < 0) goto inner_err_cleanup;

        inner_error = false;

        inner_err_cleanup:
        free(file_buffer);
        if (inner_error) goto err_cleanup;
    }

    status = 0;

    err_cleanup:
    if (file_close(&out) < 0) status = -1;
    return status;
}

static int build_signature_list_usage(FILE *file, const char *parent, const char *const *argv) {
    return fprintf(
        file,
        "Usage: %s %s [OPTION]... SIGNATURE_TYPE_GUID SIGNATURE_DATA...\n"
        "\n"
        "Options:\n"
        "  -h, --help         Show this help text\n"
        "  -o, --output FILE  Output file. Defaults to stdout\n",
        parent,
        argv[0]
    );
}

int build_signature_list_main(const char *parent, int argc, const char *const *argv) {
    bool help = false;
    const char *output_file = "-";
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
        return build_signature_list_usage(stdout, parent, argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    const char *signature_type_guid = argv[argparse_pos++];
    if (signature_type_guid == NULL) {
        (void)fprintf(stderr, "ERROR: Missing SIGNATURE_TYPE_GUID\n\n");
        goto err_usage;
    }

    if (argv[argparse_pos] == NULL) {
        (void)fprintf(stderr, "ERROR: Missing SIGNATURE_DATA\n\n");
        goto err_usage;
    }

    struct efi_guid signature_type;
    if (util_parse_guid(&signature_type, signature_type_guid) != 0) {
        (void)fprintf(stderr, "ERROR: Invalid SIGNATURE_TYPE_GUID\n\n");
        goto err_usage;
    }

    return build_signature_list(
        &signature_type,
        argv + argparse_pos, (size_t)(argc - argparse_pos),
        output_file
    ) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    err_usage:
    build_signature_list_usage(stderr, parent, argv);
    return EXIT_FAILURE;
}
