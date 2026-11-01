#include "util.h"
#include "efi.h"
#include "file.h"
#include "x.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static const char
util_printable_ascii[] = " !\"#\0%&\'()*+,-./0123456789:;<=>?\0ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_\0abcdefghijklmnopqrstuvwxyz{|}~";

int util_parse_int(const char *buffer, int max_chars, uint_least32_t *out_number) {
    uint_least32_t result = 0;
    int i = 0;
    for (; i < max_chars; ++i) {
        int zero_diff = buffer[i] - '0';
        if (zero_diff < 0 || zero_diff > 9) break;
        uint_least32_t digit_value = (uint_least32_t)zero_diff;

        if (result > (0xFFFFFFFF - digit_value) / 10) return -1;
        result = result * 10 + digit_value;
    }

    if (i > 0) *out_number = result;
    return i;
}

int util_parse_hex(const char *buffer, int max_chars, uint_least32_t *out_number) {
    uint_least32_t result = 0;
    int i = 0;
    for (; i < max_chars; ++i) {
        int zero_diff = buffer[i] - '0';
        if (zero_diff < 0 || zero_diff > 9) {
            switch (buffer[i]) {
                case 'a':
                case 'A': {
                    zero_diff = 10;
                    break;
                }
                case 'b':
                case 'B': {
                    zero_diff = 11;
                    break;
                }
                case 'c':
                case 'C': {
                    zero_diff = 12;
                    break;
                }
                case 'd':
                case 'D': {
                    zero_diff = 13;
                    break;
                }
                case 'e':
                case 'E': {
                    zero_diff = 14;
                    break;
                }
                case 'f':
                case 'F': {
                    zero_diff = 15;
                    break;
                }
                default: goto done;
            }
        }
        uint_least32_t digit_value = (uint_least32_t)zero_diff;

        if (result > (0xFFFFFFFF >> 4)) return -1;
        result = (result << 4) + digit_value;
    }
    done:

    if (i > 0) *out_number = result;
    return i;
}

int util_to_printable_ascii(char c) {
    if (c == '\0') return -1;
    for (int i = 0; i < (int)x_STR_LEN(util_printable_ascii); ++i) {
        if (c == util_printable_ascii[i]) return 32 + i;
    }
    return -1;
}

char util_from_printable_ascii(unsigned char ascii) {
    if (ascii < 32 || ascii >= 32 + x_STR_LEN(util_printable_ascii)) return '\0';
    return util_printable_ascii[ascii - 32];
}

int util_parse_guid(struct efi_guid *guid, const char *buffer) {
    uint_least32_t parsed;
    int num_parsed = util_parse_hex(buffer, 8, &parsed);
    if (num_parsed != 8 || buffer[num_parsed] != '-') return -1;
    guid->data1 = (unsigned)parsed;
    buffer += num_parsed + 1;

    num_parsed = util_parse_hex(buffer, 4, &parsed);
    if (num_parsed != 4 || buffer[num_parsed] != '-') return -1;
    guid->data2 = (unsigned)parsed;
    buffer += num_parsed + 1;

    num_parsed = util_parse_hex(buffer, 4, &parsed);
    if (num_parsed != 4 || buffer[num_parsed] != '-') return -1;
    guid->data3 = (unsigned)parsed;
    buffer += num_parsed + 1;

    for (int i = 0; i < 2; ++i) {
        num_parsed = util_parse_hex(buffer, 2, &parsed);
        if (num_parsed != 2) return -1;
        guid->data4[i] = (unsigned char)parsed;
        buffer += num_parsed;
    }
    if (*buffer != '-') return -1;
    ++buffer;
    for (int i = 2; i < 8; ++i) {
        num_parsed = util_parse_hex(buffer, 2, &parsed);
        if (num_parsed != 2) return -1;
        guid->data4[i] = (unsigned char)parsed;
        buffer += num_parsed;
    }
    if (*buffer != '\0') return -1;
    return 0;
}

void util_print_guid(const struct efi_guid *guid, char *buffer) {
    const char *hex_table = "0123456789abcdef";

    char *pos = buffer;
    for (int i = 0; i < 4; ++i) {
        *pos++ = hex_table[(guid->data1 >> (28 - 8 * i)) & 0xF];
        *pos++ = hex_table[(guid->data1 >> (24 - 8 * i)) & 0xF];
    }
    *pos++ = '-';

    for (int i = 0; i < 2; ++i) {
        *pos++ = hex_table[(guid->data2 >> (12 - 8 * i)) & 0xF];
        *pos++ = hex_table[(guid->data2 >> (8 - 8 * i)) & 0xF];
    }
    *pos++ = '-';

    for (int i = 0; i < 2; ++i) {
        *pos++ = hex_table[(guid->data3 >> (12 - 8 * i)) & 0xF];
        *pos++ = hex_table[(guid->data3 >> (8 - 8 * i)) & 0xF];
    }
    *pos++ = '-';

    for (int i = 0; i < 8; ++i) {
        unsigned char data = guid->data4[i];
        *pos++ = hex_table[(data >> 4) & 0xF];
        *pos++ = hex_table[data & 0xF];
        if (i == 1) *pos++ = '-';
    }
    *pos = '\0';
}

int util_parse_timestamp(struct efi_time *timestamp, const char *buffer) {
    uint_least32_t parsed;
    int num_parsed = util_parse_int(buffer, 4, &parsed);
    if (num_parsed != 4 || parsed < 1900 || parsed > 9999 || buffer[num_parsed] != '-') return -1;
    unsigned year = (unsigned)parsed;
    buffer += num_parsed + 1;

    num_parsed = util_parse_int(buffer, 2, &parsed);
    if (num_parsed != 2 || parsed < 1 || parsed > 12 || buffer[num_parsed] != '-') return -1;
    unsigned char month = (unsigned char)parsed;
    buffer += num_parsed + 1;

    num_parsed = util_parse_int(buffer, 2, &parsed);
    if (num_parsed != 2 || parsed < 1 || parsed > 31 || buffer[num_parsed] != ' ') return -1;
    unsigned char day = (unsigned char)parsed;
    buffer += num_parsed + 1;

    num_parsed = util_parse_int(buffer, 2, &parsed);
    if (num_parsed != 2 || parsed > 23 || buffer[num_parsed] != ':') return -1;
    unsigned char hour = (unsigned char)parsed;
    buffer += num_parsed + 1;

    num_parsed = util_parse_int(buffer, 2, &parsed);
    if (num_parsed != 2 || parsed > 59 || buffer[num_parsed] != ':') return -1;
    unsigned char minute = (unsigned char)parsed;
    buffer += num_parsed + 1;

    num_parsed = util_parse_int(buffer, 2, &parsed);
    if (num_parsed != 2 || parsed > 59 || buffer[num_parsed] != '\0') return -1;
    unsigned char second = (unsigned char)parsed;

    timestamp->year = year;
    timestamp->month = month;
    timestamp->day = day;
    timestamp->hour = hour;
    timestamp->minute = minute;
    timestamp->second = second;
    timestamp->pad1 = 0;
    timestamp->nanosecond = 0;
    timestamp->timezone = 0;
    timestamp->daylight = 0;
    timestamp->pad2 = 0;
    return 0;
}

void util_print_timestamp(const struct efi_time *timestamp, char *buffer_end) {
    char *pos = buffer_end;
    unsigned n;

    *--pos = '\0';
    n = timestamp->second;
    for (int i = 0; i < 2; ++i) { *--pos = (char)('0' + n % 10); n /= 10; }
    *--pos = ':';
    n = timestamp->minute;
    for (int i = 0; i < 2; ++i) { *--pos = (char)('0' + n % 10); n /= 10; }
    *--pos = ':';
    n = timestamp->hour;
    for (int i = 0; i < 2; ++i) { *--pos = (char)('0' + n % 10); n /= 10; }
    *--pos = ' ';
    n = timestamp->day;
    for (int i = 0; i < 2; ++i) { *--pos = (char)('0' + n % 10); n /= 10; }
    *--pos = '-';
    n = timestamp->month;
    for (int i = 0; i < 2; ++i) { *--pos = (char)('0' + n % 10); n /= 10; }
    *--pos = '-';
    n = timestamp->year;
    for (int i = 0; i < 4; ++i) { *--pos = (char)('0' + n % 10); n /= 10; }
}

#define READ_SIZE 4096
int util_read_full(const char *file, unsigned char **out_buffer, size_t *out_size) {
    struct file in;
    file_init(&in);
    unsigned char *buffer = NULL;

    if (file_open(&in, file, 0) < 0) goto err_cleanup;

    size_t size = 0;
    for (;;) {
        unsigned char *new_buffer = realloc(buffer, size + READ_SIZE);
        if (new_buffer == NULL) goto err_cleanup;
        buffer = new_buffer;

        size_t num_read;
        int read_status = file_read(&in, buffer + size, READ_SIZE, &num_read);
        if (read_status < 0) goto err_cleanup;
        size += num_read;
        if (size > x_SAFE_SIZE) goto err_cleanup;
        if (read_status == 0) break;
    }
    (void)file_close(&in);

    *out_buffer = buffer;
    *out_size = size;
    return 0;

    err_cleanup:
    (void)file_close(&in);
    free(buffer);
    return -1;
}
#undef READ_SIZE

#define READ_SIZE 4096
int util_read_full_string(const char *file, char **out_string, size_t *out_len) {
    struct file in;
    file_init(&in);
    char *string = NULL;

    if (file_open(&in, file, FILE_MODE_TEXT) < 0) goto err_cleanup;

    size_t len = 0;
    for (;;) {
        char *new_string = realloc(string, len + READ_SIZE);
        if (new_string == NULL) goto err_cleanup;
        string = new_string;

        int gets_status = file_gets(&in, string + len, READ_SIZE);
        if (gets_status < 0) goto err_cleanup;
        size_t num_read = strlen(string + len);
        len += num_read;
        if (len + 1 > x_SAFE_SIZE) goto err_cleanup;
        if (gets_status == 0) break;
    }
    (void)file_close(&in);

    *out_string = string;
    *out_len = len;
    return 0;

    err_cleanup:
    (void)file_close(&in);
    free(string);
    return -1;
}
#undef READ_SIZE

int util_concatenate(const char *const *input_files, const char *output_file) {
    int status = -1;
    struct file out;
    file_init(&out);

    if (file_open(&out, output_file, FILE_MODE_WRITE) < 0) goto err_cleanup;

    for (const char *const *file_iter = input_files; *file_iter != NULL; ++file_iter) {
        unsigned char *buffer;
        size_t size;
        if (util_read_full(*file_iter, &buffer, &size) < 0) goto err_cleanup;
        int write_status = file_write(&out, buffer, size);
        free(buffer);
        if (write_status < 0) goto err_cleanup;
    }

    status = 0;

    err_cleanup:
    if (file_close(&out) < 0) status = -1;
    return status;
}

static const uint_least32_t util_supported_attributes[] = {
    EFI_VARIABLE_NON_VOLATILE,
    EFI_VARIABLE_BOOTSERVICE_ACCESS,
    EFI_VARIABLE_RUNTIME_ACCESS,
    EFI_VARIABLE_APPEND_WRITE,
    EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
};

static const char *util_supported_attributes_args[] = {
    "--non-volatile",
    "--bootservice-access",
    "--runtime-access",
    "--append-write",
    "--time-based-auth-access",
};

int util_puts_attribute_args(uint_least32_t attributes) {
    bool first = true;
    uint_least32_t supported_attributes_mask = 0;
    for (size_t i = 0; i < x_ARRAY_LEN(util_supported_attributes); ++i) {
        uint_least32_t attribute = util_supported_attributes[i];
        supported_attributes_mask |= attribute;

        if (attributes & attribute) {
            if (first) first = false; else if (fputs(" ", stdout) == EOF) return -1;
            if (fputs(util_supported_attributes_args[i], stdout) == EOF) return -1;
        }
    }
    if ((attributes & supported_attributes_mask) != attributes) return -1;
    return 0;
}
