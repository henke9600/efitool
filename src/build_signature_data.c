#include "build_signature_data.h"
#include "argparse.h"
#include "efi.h"
#include "file.h"
#include "util.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int build_signature_data(struct efi_guid *owner, char *input, char *output_sig_data) {
    int status = -1;
    unsigned char *input_buffer = NULL;
    struct file out;
    file_init(&out);

    size_t input_size;
    if (util_read_full(input, &input_buffer, &input_size) < 0) goto err_cleanup;

    if (file_open(&out, output_sig_data, FILE_MODE_WRITE) < 0) goto err_cleanup;

    {
        struct efi_signature_data efi_sig_data;
        memcpy(&efi_sig_data.signature_owner, owner, sizeof(*owner));

        unsigned char bytes[EFI_SIGNATURE_DATA_SIZE];
        efi_signature_data_write(&efi_sig_data, &bytes[0]);
        if (file_write(&out, &bytes[0], sizeof(bytes)) < 0) goto err_cleanup;
    }

    if (file_write(&out, input_buffer, input_size) < 0) goto err_cleanup;

    status = 0;

    err_cleanup:
    free(input_buffer);
    if (file_close(&out) < 0) status = -1;
    return status;
}

static int build_signature_data_usage(FILE *file, char *parent, char **argv) {
    return fprintf(
        file,
        "Usage: %s %s [OPTION]... OWNER_GUID DATA\n"
        "\n"
        "Options:\n"
        "  -h, --help         Show this help text\n"
        "  -o, --output FILE  Output file. Defaults to stdout\n",
        parent,
        argv[0]
    );
}

int build_signature_data_main(char *parent, char **argv) {
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
        return build_signature_data_usage(stdout, parent, argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    char *owner_guid = argv[argparse_pos++];
    if (owner_guid == NULL) {
        (void)fprintf(stderr, "ERROR: Missing OWNER_GUID\n\n");
        goto err_usage;
    }

    char *data = argv[argparse_pos++];
    if (data == NULL) {
        (void)fprintf(stderr, "ERROR: Missing DATA\n\n");
        goto err_usage;
    }

    if (argv[argparse_pos] != NULL) {
        (void)fprintf(stderr, "ERROR: Too many arguments\n\n");
        goto err_usage;
    }

    struct efi_guid owner;
    if (util_parse_guid(&owner, owner_guid) != 0) {
        (void)fprintf(stderr, "ERROR: Invalid OWNER_GUID\n\n");
        goto err_usage;
    }

    return build_signature_data(&owner, data, output_file) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    err_usage:
    build_signature_data_usage(stderr, parent, argv);
    return EXIT_FAILURE;

}
