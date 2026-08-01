#ifndef UTIL_H
#define UTIL_H

#include "efi.h"
#include "x.h"

#include <stddef.h>
#include <stdint.h>

int util_to_printable_ascii(char c);
char util_from_printable_ascii(unsigned char ascii);
int util_parse_int(char *buffer, int max_chars, uint_least32_t *out_number);
int util_parse_hex(char *buffer, int max_chars, uint_least32_t *out_number);
int util_parse_guid(struct efi_guid *guid, char *buffer);
#define UTIL_PRINT_GUID_BUFFER_SIZE x_ARRAY_LEN("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
void util_print_guid(struct efi_guid *guid, char *buffer);
int util_parse_timestamp(struct efi_time *timestamp, char *buffer);
#define UTIL_PRINT_TIMESTAMP_BUFFER_SIZE x_ARRAY_LEN("1970-01-01 00:00:00")
void util_print_timestamp(struct efi_time *timestamp, char *buffer_end);
int util_read_full(char *file, unsigned char **out_buffer, size_t *out_size);
int util_read_full_string(char *file, char **out_string, size_t *out_len);
int util_concatenate(char **input_files, char *output_file);
int util_puts_attribute_args(uint_least32_t attributes);

#endif
