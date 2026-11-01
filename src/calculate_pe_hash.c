#include "calculate_pe_hash.h"
#include "argparse.h"
#include "file.h"
#include "util.h"
#include "pe.h"
#include "sha256.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int calculate_pe_hash(const char *input_pe, const char *output_sha256) {
    int status = -1;
    unsigned char *input_buffer = NULL;
    struct file out;
    file_init(&out);

    size_t input_size;
    if (util_read_full(input_pe, &input_buffer, &input_size) < 0) goto err_cleanup;

    size_t checksum_offset;
    struct pe_data_directory certificate_table;
    size_t certificate_table_offset;
    unsigned char pe_hash[SHA256_HASH_SIZE];
    if (pe_parse(
        input_buffer, input_size,
        &checksum_offset,
        &certificate_table, &certificate_table_offset,
        &pe_hash[0]
    ) < 0) {
        (void)fprintf(stderr, "ERROR: Input file is not a valid PE image\n");
        goto err_cleanup;
    }

    if (file_open(&out, output_sha256, FILE_MODE_WRITE) < 0) goto err_cleanup;
    if (file_write(&out, &pe_hash[0], sizeof(pe_hash)) < 0) goto err_cleanup;

    status = 0;

    err_cleanup:
    free(input_buffer);
    if (file_close(&out) < 0) status = -1;
    return status;
}

static int calculate_pe_hash_usage(FILE *file, const char *parent, const char *const *argv) {
    return fprintf(
        file,
        "Usage: %s %s [OPTION]... PE_IMAGE\n"
        "\n"
        "Options:\n"
        "  -h, --help         Show this help text\n"
        "  -o, --output FILE  Output file. Defaults to stdout\n",
        parent,
        argv[0]
    );
}

int calculate_pe_hash_main(const char *parent, const char *const *argv) {
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
        return calculate_pe_hash_usage(stdout, parent, argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    const char *pe_image = argv[argparse_pos++];
    if (pe_image == NULL) {
        (void)fprintf(stderr, "ERROR: Missing PE_IMAGE\n\n");
        goto err_usage;
    }

    if (argv[argparse_pos] != NULL) {
        (void)fprintf(stderr, "ERROR: Too many arguments\n\n");
        goto err_usage;
    }

    return calculate_pe_hash(pe_image, output_file) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    err_usage:
    calculate_pe_hash_usage(stderr, parent, argv);
    return EXIT_FAILURE;
}
