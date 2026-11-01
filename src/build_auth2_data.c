#include "build_auth2_data.h"
#include "argparse.h"
#include "efi.h"
#include "file.h"
#include "util.h"
#include "asn1.h"
#include "x.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int build_auth2_data(
    const struct efi_time *timestamp,
    const char *input_var_data,
    const char *input_signature,
    const char *input_x509,
    const char *output_auth2_data
) {
    int status = -1;
    unsigned char *input_var_data_buffer = NULL;
    unsigned char *input_signature_buffer = NULL;
    unsigned char *input_x509_buffer = NULL;
    struct file out;
    file_init(&out);
    unsigned char *signed_data = NULL;

    size_t input_var_data_size;
    if (util_read_full(input_var_data, &input_var_data_buffer, &input_var_data_size) < 0) goto err_cleanup;

    size_t input_signature_size;
    if (util_read_full(input_signature, &input_signature_buffer, &input_signature_size) < 0) goto err_cleanup;

    size_t input_x509_size;
    if (util_read_full(input_x509, &input_x509_buffer, &input_x509_size) < 0) goto err_cleanup;

    const unsigned char *serial_number;
    size_t serial_number_size;
    const unsigned char *issuer;
    size_t issuer_size;
    if (asn1_parse_x509(
        input_x509_buffer, input_x509_size,
        &serial_number, &serial_number_size,
        &issuer, &issuer_size
    ) < 0) goto err_cleanup;

    if (input_x509_size + serial_number_size + issuer_size > x_SAFE_SIZE - input_signature_size) goto err_cleanup;

    struct asn1_pkcs7_signed_data_content_info_ctx signed_data_ctx;
    size_t signed_data_size = asn1_pkcs7_signed_data_content_info_write(
        &signed_data_ctx,
        &asn1_pkcs7_data_obj[0], x_ARRAY_LEN(asn1_pkcs7_data_obj),
        NULL, 0,
        input_x509_buffer, input_x509_size,
        issuer, issuer_size,
        serial_number, serial_number_size,
        NULL, 0,
        input_signature_buffer, input_signature_size,
        NULL
    );

    if (file_open(&out, output_auth2_data, FILE_MODE_WRITE) < 0) goto err_cleanup;

    {
        struct efi_variable_authentication_2 auth2;
        memcpy(&auth2.timestamp, timestamp, sizeof(*timestamp));
        auth2.auth_info.hdr.length = (uint_least32_t)(WIN_CERTIFICATE_UEFI_GUID_SIZE + signed_data_size);
        auth2.auth_info.hdr.revision = 0x0200;
        auth2.auth_info.hdr.certificate_type = WIN_CERT_TYPE_EFI_GUID;
        memcpy(&auth2.auth_info.cert_type, &efi_cert_type_pkcs7_guid, sizeof(efi_cert_type_pkcs7_guid));

        unsigned char bytes[EFI_VARIABLE_AUTHENTICATION_2_SIZE];
        efi_variable_authentication_2_write(&auth2, &bytes[0]);
        if (file_write(&out, &bytes[0], sizeof(bytes)) < 0) goto err_cleanup;
    }

    signed_data = malloc(signed_data_size);
    if (signed_data == NULL) goto err_cleanup;

    asn1_pkcs7_signed_data_content_info_write(
        &signed_data_ctx,
        &asn1_pkcs7_data_obj[0], x_ARRAY_LEN(asn1_pkcs7_data_obj),
        NULL, 0,
        input_x509_buffer, input_x509_size,
        issuer, issuer_size,
        serial_number, serial_number_size,
        NULL, 0,
        input_signature_buffer, input_signature_size,
        signed_data
    );
    if (file_write(&out, signed_data, signed_data_size) < 0) goto err_cleanup;
    if (file_write(&out, input_var_data_buffer, input_var_data_size) < 0) goto err_cleanup;

    status = 0;

    err_cleanup:
    free(input_var_data_buffer);
    free(input_signature_buffer);
    free(input_x509_buffer);
    if (file_close(&out) < 0) status = -1;
    free(signed_data);
    return status;
}

#define TIMESTAMP_DEFAULT "1970-01-01 00:00:00"
#define TIMESTAMP_INFO "formatted as \"%%Y-%%m-%%d %%H:%%M:%%S\". Defaults to \""
static int build_auth2_data_usage(FILE *file, const char *parent, const char *const *argv) {
    return fprintf(
        file,
        "Usage: %s %s [OPTION]... CERTIFICATE SIGNATURE VARIABLE_DATA\n"
        "\n"
        "Options:\n"
        "  -h, --help                 Show this help text\n"
        "  -o, --output FILE          Output file. Defaults to stdout\n"
        "  -t, --timestamp TIMESTAMP  Set authentication timestamp " TIMESTAMP_INFO TIMESTAMP_DEFAULT "\"\n",
        parent,
        argv[0]
    );
}
#undef TIMESTAMP_INFO

int build_auth2_data_main(const char *parent, const char *const *argv) {
    bool help = false;
    const char *output_file = "-";
    struct efi_time timestamp;
    util_parse_timestamp(&timestamp, TIMESTAMP_DEFAULT);
    ARGPARSE_BEGIN(argv)
        if (strcmp(argparse_long_opt, "help") == 0)      { argparse_arg = "h"; break; }
        if (strcmp(argparse_long_opt, "output") == 0)    { argparse_arg = "o"; break; }
        if (strcmp(argparse_long_opt, "timestamp") == 0) { argparse_arg = "t"; break; }
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
        return build_auth2_data_usage(stdout, parent, argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    const char *certificate = argv[argparse_pos++];
    if (certificate == NULL) {
        (void)fprintf(stderr, "ERROR: Missing CERTIFICATE\n\n");
        goto err_usage;
    }

    const char *signature = argv[argparse_pos++];
    if (signature == NULL) {
        (void)fprintf(stderr, "ERROR: Missing SIGNATURE\n\n");
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

    return build_auth2_data(
        &timestamp,
        variable_data,
        signature,
        certificate,
        output_file
    ) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    err_usage:
    build_auth2_data_usage(stderr, parent, argv);
    return EXIT_FAILURE;
}
#undef TIMESTAMP_DEFAULT
