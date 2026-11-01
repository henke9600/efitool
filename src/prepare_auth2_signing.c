#include "prepare_auth2_signing.h"
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

static int prepare_auth2_signing(
    const unsigned char *var_name_ucs2, size_t var_name_ucs2_size,
    const struct efi_guid *vendor_guid,
    uint_least32_t attributes,
    const struct efi_time *timestamp,
    const char *input_var_data,
    const char *output_to_be_signed
) {
    int status = -1;
    unsigned char *input_buffer = NULL;
    struct file out;
    file_init(&out);

    size_t input_size;
    if (util_read_full(input_var_data, &input_buffer, &input_size) < 0) goto err_cleanup;

    if (file_open(&out, output_to_be_signed, FILE_MODE_WRITE) < 0) goto err_cleanup;

    if (file_write(&out, var_name_ucs2, var_name_ucs2_size) < 0) goto err_cleanup;
    {
        unsigned char bytes[EFI_GUID_SIZE];
        efi_guid_write(vendor_guid, &bytes[0]);
        if (file_write(&out, &bytes[0], sizeof(bytes)) < 0) goto err_cleanup;
    }
    {
        unsigned char bytes[4];
        x_store_u32(attributes, &bytes[0]);
        if (file_write(&out, &bytes[0], sizeof(bytes)) < 0) goto err_cleanup;
    }
    {
        unsigned char bytes[EFI_TIME_SIZE];
        efi_time_write(timestamp, &bytes[0]);
        if (file_write(&out, &bytes[0], sizeof(bytes)) < 0) goto err_cleanup;
    }
    if (file_write(&out, input_buffer, input_size) < 0) goto err_cleanup;

    status = 0;

    err_cleanup:
    free(input_buffer);
    if (file_close(&out) < 0) status = -1;
    return status;
}

#define TIMESTAMP_DEFAULT "1970-01-01 00:00:00"
#define TIMESTAMP_INFO "formatted as \"%%Y-%%m-%%d %%H:%%M:%%S\". Defaults to \""
static int prepare_auth2_signing_usage(FILE *file, const char *parent, const char *const *argv) {
    return fprintf(
        file,
        "Usage: %s %s [OPTION]... VARIABLE_NAME VENDOR_GUID VARIABLE_DATA\n"
        "\n"
        "Options:\n"
        "  -h, --help                 Show this help text\n"
        "  -o, --output FILE          Output file. Defaults to stdout\n"
        "  -n, --non-volatile         Set the non-volatile attribute\n"
        "  -b, --bootservice-access   Set the bootservice access attribute\n"
        "  -r, --runtime-access       Set the runtime access attribute\n"
        "  -a, --append-write         Set the append write attribute\n"
        "  -t, --timestamp TIMESTAMP  Set authentication timestamp " TIMESTAMP_INFO TIMESTAMP_DEFAULT "\"\n",
        parent,
        argv[0]
    );
}
#undef TIMESTAMP_INFO

int prepare_auth2_signing_main(const char *parent, const char *const *argv) {
    bool help = false;
    const char *output_file = "-";
    uint_least32_t attributes = EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
    struct efi_time timestamp;
    util_parse_timestamp(&timestamp, TIMESTAMP_DEFAULT);
    ARGPARSE_BEGIN(argv)
        if (strcmp(argparse_long_opt, "help") == 0)               { argparse_arg = "h"; break; }
        if (strcmp(argparse_long_opt, "output") == 0)             { argparse_arg = "o"; break; }
        if (strcmp(argparse_long_opt, "non-volatile") == 0)       { argparse_arg = "n"; break; }
        if (strcmp(argparse_long_opt, "bootservice-access") == 0) { argparse_arg = "b"; break; }
        if (strcmp(argparse_long_opt, "runtime-access") == 0)     { argparse_arg = "r"; break; }
        if (strcmp(argparse_long_opt, "append-write") == 0)       { argparse_arg = "a"; break; }
        if (strcmp(argparse_long_opt, "timestamp") == 0)          { argparse_arg = "t"; break; }
    ARGPARSE_LONG_OPTS_TO_FLAGS_DELIMITER
        case 'h': {
            help = true;
            break;
        }
        case 'n': {
            attributes |= EFI_VARIABLE_NON_VOLATILE;
            break;
        }
        case 'b': {
            attributes |= EFI_VARIABLE_BOOTSERVICE_ACCESS;
            break;
        }
        case 'r': {
            attributes |= EFI_VARIABLE_RUNTIME_ACCESS;
            break;
        }
        case 'a': {
            attributes |= EFI_VARIABLE_APPEND_WRITE;
            break;
        }
    ARGPARSE_FLAGS_TO_ARGS_DELIMITER
        case 'o': {
            output_file = argparse_arg;
            break;
        }
        case 't': {
            if (util_parse_timestamp(&timestamp, argparse_arg) < 0) goto argparse_done;
            break;
        }
    ARGPARSE_END

    if (argparse_opt != '\0') {
        if (argparse_long_opt != NULL) (void)fprintf(stderr, "ERROR: Invalid long option '%s'\n\n", argparse_long_opt);
        else                           (void)fprintf(stderr, "ERROR: Invalid option '%c'\n\n", argparse_opt);
        goto err_usage;
    }

    if (help) {
        return prepare_auth2_signing_usage(stdout, parent, argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    const char *variable_name = argv[argparse_pos++];
    if (variable_name == NULL) {
        (void)fprintf(stderr, "ERROR: Missing VARIABLE_NAME\n\n");
        goto err_usage;
    }

    const char *vendor_guid = argv[argparse_pos++];
    if (vendor_guid == NULL) {
        (void)fprintf(stderr, "ERROR: Missing VENDOR_GUID\n\n");
        goto err_usage;
    }

    const char *variable_data = argv[argparse_pos++];
    if (variable_data == NULL) {
        (void)fprintf(stderr, "ERROR: Missing VARIABLE_DATA\n\n");
        goto err_usage;
    }

    if (argv[argparse_pos] != NULL) {
        (void)fprintf(stderr, "ERROR: Too many arguments\n\n");
        goto err_usage;
    }

    struct efi_guid vendor;
    if (util_parse_guid(&vendor, vendor_guid) != 0) {
        (void)fprintf(stderr, "ERROR: Invalid VENDOR_GUID\n\n");
        goto err_usage;
    }

    size_t variable_name_len = strlen(variable_name);
    if (
        variable_name_len == 0 ||
        variable_name_len > x_SAFE_SIZE / 2
    ) goto err_usage;
    size_t var_name_ucs2_size = variable_name_len * 2;
    unsigned char *var_name_ucs2 = malloc(var_name_ucs2_size);
    if (var_name_ucs2 == NULL) goto err_usage;

    for (size_t i = 0; i < variable_name_len; ++i) {
        int ascii = util_to_printable_ascii(variable_name[i]);
        if (ascii < 0) {
            (void)fprintf(stderr, "ERROR: Invalid VARIABLE_NAME\n\n");
            free(var_name_ucs2);
            goto err_usage;
        }
        size_t ucs_i = i * 2;
        var_name_ucs2[ucs_i] = (unsigned char)ascii;
        var_name_ucs2[ucs_i + 1] = 0;
    }

    int status = prepare_auth2_signing(
        var_name_ucs2, var_name_ucs2_size,
        &vendor,
        attributes,
        &timestamp,
        variable_data,
        output_file
    );
    free(var_name_ucs2);
    return status < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    err_usage:
    prepare_auth2_signing_usage(stderr, parent, argv);
    return EXIT_FAILURE;
}
#undef TIMESTAMP_DEFAULT
