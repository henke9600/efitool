#include "build_signed_pe.h"
#include "argparse.h"
#include "asn1.h"
#include "sha256.h"
#include "pe.h"
#include "efi.h"
#include "file.h"
#include "util.h"
#include "x.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int build_signed_pe(
    char *input_pe,
    char *input_signature,
    char *input_x509,
    char *output_pe
) {
    int status = -1;
    unsigned char *input_pe_buffer = NULL;
    unsigned char *input_signature_buffer = NULL;
    unsigned char *input_x509_buffer = NULL;
    unsigned char *auth_attrs = NULL;
    unsigned char *spcidc = NULL;
    unsigned char *win_cert_buffer = NULL;
    struct file out;
    file_init(&out);

    size_t input_pe_size;
    if (util_read_full(input_pe, &input_pe_buffer, &input_pe_size) < 0) goto err_cleanup;

    size_t input_signature_size;
    if (util_read_full(input_signature, &input_signature_buffer, &input_signature_size) < 0) goto err_cleanup;

    size_t input_x509_size;
    if (util_read_full(input_x509, &input_x509_buffer, &input_x509_size) < 0) goto err_cleanup;

    size_t checksum_offset;
    struct pe_data_directory certificate_table;
    size_t certificate_table_offset;
    unsigned char pe_hash[SHA256_HASH_SIZE];
    if (pe_parse(
        input_pe_buffer, input_pe_size,
        &checksum_offset,
        &certificate_table, &certificate_table_offset,
        &pe_hash[0]
    ) < 0) {
        (void)fprintf(stderr, "ERROR: Input file is not a valid PE image\n");
        goto err_cleanup;
    }

    // If there's no certificate table, and the file size is not a multiple of 8 bytes, then signing can't be
    // done without changing the PE hash with alignment padding
    if (certificate_table.virtual_address == 0 && input_pe_size % 8 != 0) {
        (void)fprintf(stderr, "ERROR: Unsigned PE image size is not a multiple of 8 bytes, signing it would change PE hash\n");
        goto err_cleanup;
    }

    size_t spcidc_size;
    size_t auth_attrs_size;
    size_t auth_attrs_payload_size;
    if (pe_authenticode_spcidc_auth_attrs(
        &pe_hash[0],
        &spcidc, &spcidc_size,
        &auth_attrs, &auth_attrs_size, &auth_attrs_payload_size
    ) < 0) goto err_cleanup;
    unsigned char *auth_attrs_payload = auth_attrs + (auth_attrs_size - auth_attrs_payload_size);

    unsigned char *serial_number;
    size_t serial_number_size;
    unsigned char *issuer;
    size_t issuer_size;
    if (asn1_parse_x509(
        input_x509_buffer, input_x509_size,
        &serial_number, &serial_number_size,
        &issuer, &issuer_size
    ) < 0) goto err_cleanup;

    if (input_x509_size + serial_number_size + issuer_size > x_SAFE_SIZE - input_signature_size) goto err_cleanup;

    uint_least32_t spc_indirect_data_obj[] = { 1 * 40 + 3, 6, 1, 4, 1, 311, 2, 1, 4 };
    struct asn1_pkcs7_signed_data_content_info_ctx signed_data_ctx;
    size_t signed_data_size = asn1_pkcs7_signed_data_content_info_write(
        &signed_data_ctx,
        &spc_indirect_data_obj[0], x_ARRAY_LEN(spc_indirect_data_obj),
        spcidc, spcidc_size,
        input_x509_buffer, input_x509_size,
        issuer, issuer_size,
        serial_number, serial_number_size,
        auth_attrs_payload, auth_attrs_payload_size,
        input_signature_buffer, input_signature_size,
        NULL
    );

    size_t win_cert_offset = (certificate_table.virtual_address == 0) ? input_pe_size : (size_t)certificate_table.virtual_address;
    size_t win_cert_unpadded_size = WIN_CERTIFICATE_SIZE + signed_data_size;
    size_t win_cert_padding = (win_cert_unpadded_size % 8 != 0) ? (8 - win_cert_unpadded_size % 8) : 0;
    size_t win_cert_size = win_cert_unpadded_size + win_cert_padding;

    // Build WIN_CERTIFICATE structure, including zero padding
    win_cert_buffer = malloc(win_cert_size);
    if (win_cert_buffer == NULL) goto err_cleanup;

    struct win_certificate win_cert;
    win_cert.length = (uint_least32_t)win_cert_size;
    win_cert.revision = 0x0200;
    win_cert.certificate_type = WIN_CERT_TYPE_PKCS_SIGNED_DATA;

    win_certificate_write(&win_cert, win_cert_buffer);
    asn1_pkcs7_signed_data_content_info_write(
        &signed_data_ctx,
        &spc_indirect_data_obj[0], x_ARRAY_LEN(spc_indirect_data_obj),
        spcidc, spcidc_size,
        input_x509_buffer, input_x509_size,
        issuer, issuer_size,
        serial_number, serial_number_size,
        auth_attrs_payload, auth_attrs_payload_size,
        input_signature_buffer, input_signature_size,
        win_cert_buffer + WIN_CERTIFICATE_SIZE
    );
    static const unsigned char zeroes[7] = {0};
    if (win_cert_padding > 0) memcpy(win_cert_buffer + win_cert_unpadded_size, &zeroes[0], win_cert_padding);

    // Update certificate table
    certificate_table.virtual_address = (uint_least32_t)win_cert_offset;
    certificate_table.size = (uint_least32_t)win_cert_size;
    pe_data_directory_write(&certificate_table, input_pe_buffer + certificate_table_offset);

    // Update checksum
    uint_least32_t checksum = 0;
    for (size_t i = 0; i + 1 < win_cert_offset; i += 2) {
        if (i >= checksum_offset && i < checksum_offset + 4) continue;
        checksum += input_pe_buffer[i] | ((uint_least32_t)input_pe_buffer[i + 1] << 8);
        checksum = ((checksum & 0xFFFFFFFF) >> 16) + (checksum & 0xFFFF);
    }
    for (size_t i = 0; i + 1 < win_cert_size; i += 2) {
        checksum += win_cert_buffer[i] | ((uint_least32_t)win_cert_buffer[i + 1] << 8);
        checksum = ((checksum & 0xFFFFFFFF) >> 16) + (checksum & 0xFFFF);
    }
    checksum += (uint_least32_t)win_cert_offset;
    checksum += (uint_least32_t)win_cert_size;
    x_store_u32(checksum, input_pe_buffer + checksum_offset);

    if (file_open(&out, output_pe, FILE_MODE_WRITE) < 0) goto err_cleanup;
    if (file_write(&out, input_pe_buffer, win_cert_offset) < 0) goto err_cleanup;
    if (file_write(&out, win_cert_buffer, win_cert_size) < 0) goto err_cleanup;

    status = 0;

    err_cleanup:
    free(input_pe_buffer);
    free(input_signature_buffer);
    free(input_x509_buffer);
    free(auth_attrs);
    free(spcidc);
    free(win_cert_buffer);
    if (file_close(&out) < 0) status = -1;
    return status;
}

static int build_signed_pe_usage(FILE *file, char *parent, char **argv) {
    return fprintf(
        file,
        "Usage: %s %s [OPTION]... CERTIFICATE SIGNATURE PE_IMAGE\n"
        "\n"
        "Options:\n"
        "  -h, --help         Show this help text\n"
        "  -o, --output FILE  Output file. Defaults to stdout\n",
        parent,
        argv[0]
    );
}

int build_signed_pe_main(char *parent, char **argv) {
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
        return build_signed_pe_usage(stdout, parent, argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    char *certificate = argv[argparse_pos++];
    if (certificate == NULL) {
        (void)fprintf(stderr, "ERROR: Missing CERTIFICATE\n\n");
        goto err_usage;
    }

    char *signature = argv[argparse_pos++];
    if (signature == NULL) {
        (void)fprintf(stderr, "ERROR: Missing SIGNATURE\n\n");
        goto err_usage;
    }

    char *pe_image = argv[argparse_pos++];
    if (pe_image == NULL) {
        (void)fprintf(stderr, "ERROR: Missing PE_IMAGE\n\n");
        goto err_usage;
    }

    if (argv[argparse_pos] != NULL) {
        (void)fprintf(stderr, "ERROR: Too many arguments\n\n");
        goto err_usage;
    }

    int status = build_signed_pe(
        pe_image,
        signature,
        certificate,
        output_file
    );
    return status < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    err_usage:
    build_signed_pe_usage(stderr, parent, argv);
    return EXIT_FAILURE;
}
