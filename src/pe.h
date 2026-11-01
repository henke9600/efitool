#ifndef PE_H
#define PE_H

#include <stdint.h>
#include <stddef.h>

#define PE_DATA_DIRECTORY_SIZE 8
struct pe_data_directory {
    uint_least32_t virtual_address;
    uint_least32_t size;
};
void pe_data_directory_read(struct pe_data_directory *self, const unsigned char *in);
void pe_data_directory_write(const struct pe_data_directory *self, unsigned char *out);

int pe_parse(
    const unsigned char *in, size_t in_size,
    size_t *out_checksum_offset,
    struct pe_data_directory *out_certificate_table, size_t *out_certificate_table_offset,
    unsigned char *out_pe_hash
);

int pe_authenticode_spcidc_auth_attrs(
    const unsigned char *pe_hash,
    unsigned char **out_spcidc, size_t *out_spcidc_size,
    unsigned char **out_auth_attrs, size_t *out_auth_attrs_size, size_t *out_auth_attrs_payload_size
);

#endif
