#include "parse_dmpstore_data.h"
#include "argparse.h"
#include "crc32.h"
#include "efi.h"
#include "file.h"
#include "util.h"
#include "x.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define CONSTANT_SIZE (4 + 4 + EFI_GUID_SIZE + 4 + 4)
#define VAR_NAME_UCS2_OFFSET 8
static int parse_dmpstore_data(const char *dmpstore_data, const char *output_data) {
    int status = -1;
    unsigned char *input_buffer = NULL;
    char *var_name = NULL;
    struct file out;
    file_init(&out);

    size_t input_size;
    if (util_read_full(dmpstore_data, &input_buffer, &input_size) < 0) goto err_cleanup;

    if (input_size < CONSTANT_SIZE) goto err_cleanup;
    size_t variable_size = input_size - CONSTANT_SIZE;

    uint_least32_t var_name_ucs2_size = x_load_u32(input_buffer);
    if (
        var_name_ucs2_size < 2 ||
        var_name_ucs2_size > variable_size ||
        var_name_ucs2_size % 2 != 0 ||
        input_buffer[VAR_NAME_UCS2_OFFSET + var_name_ucs2_size - 2] != 0 ||
        input_buffer[VAR_NAME_UCS2_OFFSET + var_name_ucs2_size - 1] != 0
    ) goto err_cleanup;

    uint_least32_t data_size = x_load_u32(input_buffer + 4);
    if (data_size != variable_size - var_name_ucs2_size) goto err_cleanup;

    uint_least32_t file_crc32 = x_load_u32(input_buffer + (input_size - 4));
    struct crc32_state crc32_state;
    crc32_state_init(&crc32_state);
    crc32_state_update(&crc32_state, input_buffer, input_size - 4);
    uint_least32_t crc32 = crc32_state_finish(&crc32_state);
    if (file_crc32 != crc32) goto err_cleanup;

    size_t var_name_size = var_name_ucs2_size / 2;
    size_t var_name_len = var_name_size - 1;
    var_name = malloc(var_name_size);
    if (var_name == NULL) goto err_cleanup;

    size_t off = VAR_NAME_UCS2_OFFSET;
    for (size_t i = 0; i < var_name_len; ++i) {
        char c = util_from_printable_ascii(input_buffer[off]);
        if (c == '\0' || input_buffer[off + 1] != 0) goto err_cleanup;
        var_name[i] = c;

        off += 2;
    }
    var_name[var_name_len] = '\0';
    off += 2;

    struct efi_guid owner;
    efi_guid_read(&owner, input_buffer + off);
    off += EFI_GUID_SIZE;

    uint_least32_t attributes = x_load_u32(input_buffer + off);
    off += 4;

    if (file_open(&out, output_data, FILE_MODE_WRITE) < 0) goto err_cleanup;
    if (file_write(&out, input_buffer + off, data_size) < 0) goto err_cleanup;

    // Write parsed header to stdout
    char owner_guid[UTIL_PRINT_GUID_BUFFER_SIZE];
    util_print_guid(&owner, &owner_guid[0]);
    if (fprintf(stdout, "%s\t%s\t", var_name, &owner_guid[0]) < 0) goto err_cleanup;

    if (util_puts_attribute_args(attributes) < 0) goto err_cleanup;
    if (fputs("\n", stdout) == EOF) goto err_cleanup;

    status = 0;

    err_cleanup:
    free(input_buffer);
    free(var_name);
    if (file_close(&out) < 0) status = -1;
    return status;
}
#undef CONSTANT_SIZE
#undef VAR_NAME_UCS2_OFFSET

static int parse_dmpstore_data_usage(FILE *file, const char *parent, const char *const *argv) {
    return fprintf(
        file,
        "Usage: %s %s [OPTION]... DMPSTORE_DATA\n"
        "\n"
        "Options:\n"
        "  -h, --help         Show this help text\n"
        "  -o, --output FILE  Output file\n",
        parent,
        argv[0]
    );
}

int parse_dmpstore_data_main(const char *parent, const char *const *argv) {
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
        return parse_dmpstore_data_usage(stdout, parent, argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    const char *dmpstore_data = argv[argparse_pos++];
    if (dmpstore_data == NULL) {
        (void)fprintf(stderr, "ERROR: Missing DMPSTORE_DATA\n\n");
        goto err_usage;
    }

    if (argv[argparse_pos] != NULL) {
        (void)fprintf(stderr, "ERROR: Too many arguments\n\n");
        goto err_usage;
    }

    crc32_init();
    return parse_dmpstore_data(dmpstore_data, output_file) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    err_usage:
    parse_dmpstore_data_usage(stderr, parent, argv);
    return EXIT_FAILURE;
}
