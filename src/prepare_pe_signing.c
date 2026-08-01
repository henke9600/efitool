#include "prepare_pe_signing.h"
#include "argparse.h"
#include "file.h"
#include "pe.h"
#include "sha256.h"
#include "util.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int prepare_pe_signing(char *input_pe_sha256, char *output_to_be_signed) {
    int status = -1;
    unsigned char *input_buffer = NULL;
    unsigned char *spcidc = NULL;
    unsigned char *auth_attrs = NULL;
    struct file out;
    file_init(&out);

    size_t input_size;
    if (util_read_full(input_pe_sha256, &input_buffer, &input_size) < 0) goto err_cleanup;
    if (input_size != SHA256_HASH_SIZE) {
        (void)fprintf(stderr, "ERROR: Input file is not a valid SHA256 hash\n");
        goto err_cleanup;
    }

    size_t spcidc_size;
    size_t auth_attrs_size;
    size_t auth_attrs_payload_size;
    if (pe_authenticode_spcidc_auth_attrs(
        input_buffer,
        &spcidc, &spcidc_size,
        &auth_attrs, &auth_attrs_size, &auth_attrs_payload_size
    ) < 0) goto err_cleanup;

    if (file_open(&out, output_to_be_signed, FILE_MODE_WRITE) < 0) goto err_cleanup;
    if (file_write(&out, auth_attrs, auth_attrs_size) < 0) goto err_cleanup;

    status = 0;

    err_cleanup:
    free(input_buffer);
    free(spcidc);
    free(auth_attrs);
    if (file_close(&out) < 0) status = -1;
    return status;
}

static int prepare_pe_signing_usage(FILE *file, char *parent, char **argv) {
    return fprintf(
        file,
        "Usage: %s %s [OPTION]... PE_HASH\n"
        "\n"
        "Options:\n"
        "  -h, --help         Show this help text\n"
        "  -o, --output FILE  Output file. Defaults to stdout\n",
        parent,
        argv[0]
    );
}

int prepare_pe_signing_main(char *parent, char **argv) {
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
        else                  (void)fprintf(stderr, "ERROR: Invalid option '%c'\n\n", argparse_opt);
        goto err_usage;
    }

    if (help) {
        return prepare_pe_signing_usage(stdout, parent, argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    char *pe_hash = argv[argparse_pos++];
    if (pe_hash == NULL) {
        (void)fprintf(stderr, "ERROR: Missing PE_HASH\n\n");
        goto err_usage;
    }

    if (argv[argparse_pos] != NULL) {
        (void)fprintf(stderr, "ERROR: Too many arguments\n\n");
        goto err_usage;
    }

    int status = prepare_pe_signing(
        pe_hash,
        output_file
    );
    return status < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    err_usage:
    prepare_pe_signing_usage(stderr, parent, argv);
    return EXIT_FAILURE;
}
