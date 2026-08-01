#include "parse_auth2_data.h"
#include "argparse.h"
#include "asn1.h"
#include "efi.h"
#include "file.h"
#include "util.h"
#include "x.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int parse_auth2_data(
    char *input_auth2_data,
    char *output_var_data,
    char *output_x509,
    char *output_sig
) {
    int status = -1;
    unsigned char *input_buffer = NULL;
    struct file out_var;
    file_init(&out_var);
    struct file out_x509;
    file_init(&out_x509);
    struct file out_sig;
    file_init(&out_sig);

    size_t input_size;
    if (util_read_full(input_auth2_data, &input_buffer, &input_size) < 0) goto err_cleanup;

    if (input_size < EFI_VARIABLE_AUTHENTICATION_2_SIZE) goto err_cleanup;
    struct efi_variable_authentication_2 auth2;
    efi_variable_authentication_2_read(&auth2, input_buffer);
    if (
        auth2.timestamp.year < 1900 || auth2.timestamp.year > 9999 ||
        auth2.timestamp.month < 1 || auth2.timestamp.month > 12 ||
        auth2.timestamp.day < 1 || auth2.timestamp.day > 31 ||
        auth2.timestamp.hour > 23 ||
        auth2.timestamp.minute > 59 ||
        auth2.timestamp.second > 59 ||
        auth2.timestamp.pad1 != 0 ||
        auth2.timestamp.nanosecond != 0 ||
        auth2.timestamp.timezone != 0 ||
        auth2.timestamp.daylight != 0 ||
        auth2.timestamp.pad2 != 0 ||
        auth2.auth_info.hdr.length < WIN_CERTIFICATE_UEFI_GUID_SIZE ||
        auth2.auth_info.hdr.length > (
            input_size - (EFI_VARIABLE_AUTHENTICATION_2_SIZE - WIN_CERTIFICATE_UEFI_GUID_SIZE)
        ) ||
        auth2.auth_info.hdr.revision != 0x0200 ||
        auth2.auth_info.hdr.certificate_type != WIN_CERT_TYPE_EFI_GUID ||
        !efi_guid_equals(&auth2.auth_info.cert_type, (struct efi_guid *)&efi_cert_type_pkcs7_guid)
    ) goto err_cleanup;

    unsigned char *x509;
    size_t x509_size;
    unsigned char *signature;
    size_t signature_size;
    size_t content_info_off = EFI_VARIABLE_AUTHENTICATION_2_SIZE;
    size_t content_info_size = auth2.auth_info.hdr.length - WIN_CERTIFICATE_UEFI_GUID_SIZE;
    if (asn1_parse_pkcs7_signed_data_content_info(
        input_buffer + content_info_off, content_info_size,
        &x509, &x509_size,
        &signature, &signature_size
    ) < 0) goto err_cleanup;

    if (file_open(&out_x509, output_x509, FILE_MODE_WRITE) < 0) goto err_cleanup;
    if (file_write(&out_x509, x509, x509_size) < 0) goto err_cleanup;

    if (file_open(&out_sig, output_sig, FILE_MODE_WRITE) < 0) goto err_cleanup;
    if (file_write(&out_sig, signature, signature_size) < 0) goto err_cleanup;

    size_t var_data_off = content_info_off + content_info_size;
    if (file_open(&out_var, output_var_data, FILE_MODE_WRITE) < 0) goto err_cleanup;
    if (file_write(&out_var, input_buffer + var_data_off, input_size - var_data_off) < 0) goto err_cleanup;

    char timestamp[UTIL_PRINT_TIMESTAMP_BUFFER_SIZE];
    util_print_timestamp(&auth2.timestamp, x_ARRAY_END(timestamp));
    if (fprintf(stdout, "%s\n", &timestamp[0]) < 0) goto err_cleanup;

    status = 0;

    err_cleanup:
    free(input_buffer);
    if (file_close(&out_var) < 0) status = -1;
    if (file_close(&out_x509) < 0) status = -1;
    if (file_close(&out_sig) < 0) status = -1;
    return status;
}

static int parse_auth2_data_usage(FILE *file, char *parent, char **argv) {
    return fprintf(
        file,
        "Usage: %s %s [OPTION]... AUTH2_DATA\n"
        "\n"
        "Options:\n"
        "  -h, --help                     Show this help text\n"
        "  -o, --output FILE              Output file for variable data\n"
        "  -c, --certificate-output FILE  Output file for certificate\n"
        "  -s, --signature-output FILE    Output file for signature\n",
        parent,
        argv[0]
    );
}

int parse_auth2_data_main(char *parent, char **argv) {
    bool help = false;
    char *output_file = NULL;
    char *output_file_cert = NULL;
    char *output_file_sig = NULL;
    ARGPARSE_BEGIN(argv)
        if (strcmp(argparse_long_opt, "help") == 0)               { argparse_arg = "h"; break; }
        if (strcmp(argparse_long_opt, "output") == 0)             { argparse_arg = "o"; break; }
        if (strcmp(argparse_long_opt, "certificate-output") == 0) { argparse_arg = "c"; break; }
        if (strcmp(argparse_long_opt, "signature-output") == 0)   { argparse_arg = "s"; break; }
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
        case 'c': {
            if (strcmp(argparse_arg, "-") == 0) goto argparse_done;
            output_file_cert = argparse_arg;
            break;
        }
        case 's': {
            if (strcmp(argparse_arg, "-") == 0) goto argparse_done;
            output_file_sig = argparse_arg;
            break;
        }
    ARGPARSE_END

    if (argparse_opt != '\0') {
        if (argparse_long_opt != NULL) (void)fprintf(stderr, "ERROR: Invalid long option '%s'\n\n", argparse_long_opt);
        else                           (void)fprintf(stderr, "ERROR: Invalid option '%c'\n\n", argparse_opt);
        goto err_usage;
    }

    if (help) {
        return parse_auth2_data_usage(stdout, parent, argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    char *auth2_data = argv[argparse_pos++];
    if (auth2_data == NULL) {
        (void)fprintf(stderr, "ERROR: Missing AUTH2_DATA\n\n");
        goto err_usage;
    }

    if (argv[argparse_pos] != NULL) {
        (void)fprintf(stderr, "ERROR: Too many arguments\n\n");
        goto err_usage;
    }

    return parse_auth2_data(auth2_data, output_file, output_file_cert, output_file_sig) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    err_usage:
    parse_auth2_data_usage(stderr, parent, argv);
    return EXIT_FAILURE;
}
