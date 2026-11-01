#include "pe.h"
#include "asn1.h"
#include "sha256.h"
#include "x.h"

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

// "MZ"
#define PE_DOS_MAGIC_0 77
#define PE_DOS_MAGIC_1 90
#define PE_FILE_ADDRESS_DOS_OFFSET 0x3C

// "PE\0\0"
#define PE_SIGNATURE_0 80
#define PE_SIGNATURE_1 69
#define PE_SIGNATURE_2 0
#define PE_SIGNATURE_3 0

#define PE_MAGIC_32 0x10B
#define PE_MAGIC_32_PLUS 0x20B

#define PE_COFF_SIZE 20

#define PE_OPTIONAL_CHECK_SUM_OFFSET 64
#define PE_CERTIFICATE_TABLE_INDEX 4

#define PE_SECTION_HEADER_SIZE 40
struct pe_section_header {
    uint_least32_t size_of_raw_data;
    uint_least32_t pointer_to_raw_data;
};
static void pe_section_header_read(struct pe_section_header *self, const unsigned char *in) {
    self->size_of_raw_data = x_load_u32(in + 16);
    self->pointer_to_raw_data = x_load_u32(in + 20);
}

void pe_data_directory_read(struct pe_data_directory *self, const unsigned char *in) {
    self->virtual_address = x_load_u32(in);
    self->size = x_load_u32(in + 4);
}
void pe_data_directory_write(const struct pe_data_directory *self, unsigned char *out) {
    x_store_u32(self->virtual_address, out);
    x_store_u32(self->size, out + 4);
}

int pe_parse(
    const unsigned char *in, size_t in_size,
    size_t *out_checksum_offset,
    struct pe_data_directory *out_certificate_table, size_t *out_certificate_table_offset,
    unsigned char *out_pe_hash
) {
    if (
        PE_FILE_ADDRESS_DOS_OFFSET + 4 > in_size ||
        in[0] != PE_DOS_MAGIC_0 ||
        in[1] != PE_DOS_MAGIC_1
    ) return -1;

    uint_least32_t pe_file_address = x_load_u32(in + PE_FILE_ADDRESS_DOS_OFFSET);
    if (pe_file_address > x_SAFE_SIZE || pe_file_address % 4 != 0) return -1;

    size_t pe_coff_offset = pe_file_address + 4;
    size_t pe_optional_offset = pe_coff_offset + PE_COFF_SIZE;
    if (pe_optional_offset + 2 > in_size) return -1;

    if (
        in[pe_file_address] != PE_SIGNATURE_0 ||
        in[pe_file_address + 1] != PE_SIGNATURE_1 ||
        in[pe_file_address + 2] != PE_SIGNATURE_2 ||
        in[pe_file_address + 3] != PE_SIGNATURE_3
    ) return -1;

    size_t number_of_sections = x_load_u16(in + pe_coff_offset + 2);
    size_t size_of_optional_header = x_load_u16(in + pe_coff_offset + 16);
    unsigned pe_magic = x_load_u16(in + pe_optional_offset);
    if (pe_magic != PE_MAGIC_32 && pe_magic != PE_MAGIC_32_PLUS) return -1;

    size_t certificate_table_offset = (
        pe_optional_offset +
        (pe_magic == PE_MAGIC_32 ? 96 : 112) +
        (size_t)(PE_DATA_DIRECTORY_SIZE * PE_CERTIFICATE_TABLE_INDEX)
    );
    if (size_of_optional_header > in_size - pe_optional_offset) return -1;
    size_t section_headers_offset = pe_optional_offset + size_of_optional_header;
    if (section_headers_offset < certificate_table_offset + PE_DATA_DIRECTORY_SIZE) return -1;
    if (number_of_sections > (in_size - section_headers_offset) / PE_SECTION_HEADER_SIZE) return -1;

    uint_least32_t size_of_headers = x_load_u32(in + pe_optional_offset + 60);
    if (
        size_of_headers > in_size ||
        size_of_headers < section_headers_offset + number_of_sections * PE_SECTION_HEADER_SIZE
    ) return -1;

    struct pe_data_directory certificate_table;
    pe_data_directory_read(&certificate_table, in + certificate_table_offset);

    // We need the certificate table to either not exist, or to be at the end of the file with 8 byte alignment
    if (
        (certificate_table.virtual_address != 0 || certificate_table.size != 0) &&
        (
            certificate_table.size > in_size ||
            certificate_table.virtual_address != in_size - certificate_table.size ||
            (certificate_table.virtual_address % 8) != 0
        )
    ) return -1;

    struct pe_section_header *section_headers = NULL;
    if (number_of_sections > 0) {
        if (number_of_sections > SIZE_MAX / sizeof(*section_headers)) return -1;
        section_headers = malloc(number_of_sections * sizeof(*section_headers));
        if (section_headers == NULL) return -1;
    }

    for (size_t i = 0; i < number_of_sections; ++i) {
        struct pe_section_header header;
        pe_section_header_read(
            &header,
            in + (section_headers_offset + i * PE_SECTION_HEADER_SIZE)
        );

        if (
            header.pointer_to_raw_data > in_size ||
            header.size_of_raw_data > in_size - header.pointer_to_raw_data
        ) {
            free(section_headers);
            return -1;
        }

        // Insert sorted by file offset
        size_t j = i;
        for (; j > 0; --j) {
            if (header.pointer_to_raw_data >= section_headers[j - 1].pointer_to_raw_data) break;
            section_headers[j] = section_headers[j - 1];
        }
        section_headers[j] = header;
    }

    size_t checksum_offset = pe_optional_offset + PE_OPTIONAL_CHECK_SUM_OFFSET;

    struct sha256 sha256;
    sha256_init(&sha256);
    sha256_update(&sha256, in, checksum_offset);
    sha256_update(
        &sha256,
        in + (checksum_offset + 4),
        certificate_table_offset - (checksum_offset + 4)
    );
    sha256_update(
        &sha256,
        in + (certificate_table_offset + PE_DATA_DIRECTORY_SIZE),
        size_of_headers - (certificate_table_offset + PE_DATA_DIRECTORY_SIZE)
    );
    size_t num_bytes_hashed = size_of_headers;
    for (size_t i = 0; i < number_of_sections; ++i) {
        sha256_update(
            &sha256,
            in + section_headers[i].pointer_to_raw_data,
            section_headers[i].size_of_raw_data
        );
        if (section_headers[i].size_of_raw_data > in_size - num_bytes_hashed) {
            free(section_headers);
            return -1;
        }
        num_bytes_hashed += section_headers[i].size_of_raw_data;
    }
    free(section_headers);

    size_t num_extra_bytes = in_size - num_bytes_hashed;
    if (num_extra_bytes < certificate_table.size) return -1;
    sha256_update(&sha256, in + num_bytes_hashed, num_extra_bytes - certificate_table.size);
    sha256_finish(&sha256, out_pe_hash);

    *out_checksum_offset = checksum_offset;
    memcpy(out_certificate_table, &certificate_table, sizeof(certificate_table));
    *out_certificate_table_offset = certificate_table_offset;

    return 0;
}

int pe_authenticode_spcidc_auth_attrs(
    const unsigned char *pe_hash,
    unsigned char **out_spcidc, size_t *out_spcidc_size,
    unsigned char **out_auth_attrs, size_t *out_auth_attrs_size, size_t *out_auth_attrs_payload_size
) {
    struct asn1_authenticode_spcidc_ctx spcidc_ctx;
    size_t spcidc_size = asn1_authenticode_spcidc_write(&spcidc_ctx, pe_hash, NULL);
    unsigned char *spcidc = malloc(spcidc_size);
    if (spcidc == NULL) return -1;
    asn1_authenticode_spcidc_write(&spcidc_ctx, pe_hash, spcidc);

    struct sha256 sha256;
    sha256_init(&sha256);
    sha256_update(&sha256, spcidc + (spcidc_size - spcidc_ctx.payload_size), spcidc_ctx.payload_size);
    unsigned char message_digest[SHA256_HASH_SIZE];
    sha256_finish(&sha256, &message_digest[0]);

    struct asn1_authenticode_auth_attrs_ctx auth_attrs_ctx;
    size_t auth_attrs_size = asn1_authenticode_auth_attrs_write(&auth_attrs_ctx, &message_digest[0], NULL);
    unsigned char *auth_attrs = malloc(auth_attrs_size);
    if (auth_attrs == NULL) {
        free(spcidc);
        return -1;
    }
    asn1_authenticode_auth_attrs_write(&auth_attrs_ctx, &message_digest[0], auth_attrs);

    *out_spcidc = spcidc;
    *out_spcidc_size = spcidc_size;
    *out_auth_attrs = auth_attrs;
    *out_auth_attrs_size = auth_attrs_size;
    *out_auth_attrs_payload_size = auth_attrs_ctx.payload_size;
    return 0;
}
