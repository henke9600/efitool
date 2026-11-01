#ifndef EFI_H
#define EFI_H

#include <stdint.h>
#include <stdbool.h>

// Definitions from UEFI 2.11

// 7.3.2
#define EFI_GUID_SIZE 16
struct efi_guid {
    uint_least32_t data1;
    unsigned data2;
    unsigned data3;
    unsigned char data4[8];
};
void efi_guid_read(struct efi_guid *self, const unsigned char *in);
void efi_guid_write(const struct efi_guid *self, unsigned char *out);
bool efi_guid_equals(const struct efi_guid *self, const struct efi_guid *other);

// 8.2.1
#define EFI_VARIABLE_NON_VOLATILE 0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS 0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS 0x00000004
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS 0x00000020
#define EFI_VARIABLE_APPEND_WRITE 0x00000040

// 32.2.4.1
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA 0x0002
#define WIN_CERT_TYPE_EFI_GUID 0x0EF1

#define WIN_CERTIFICATE_SIZE 8
struct win_certificate {
    uint_least32_t length;
    unsigned revision;
    unsigned certificate_type;
    // unsigned char certificate[];
};
void win_certificate_read(struct win_certificate *self, const unsigned char *in);
void win_certificate_write(const struct win_certificate *self, unsigned char *out);

// 32.2.4.3
extern const struct efi_guid efi_cert_type_pkcs7_guid;

#define WIN_CERTIFICATE_UEFI_GUID_SIZE (WIN_CERTIFICATE_SIZE + EFI_GUID_SIZE)
struct win_certificate_uefi_guid {
    struct win_certificate hdr;
    struct efi_guid cert_type;
    // unsigned char cert_data[];
};
void win_certificate_uefi_guid_read(struct win_certificate_uefi_guid *self, const unsigned char *in);
void win_certificate_uefi_guid_write(const struct win_certificate_uefi_guid *self, unsigned char *out);

// 8.3.1
#define EFI_TIME_ADJUST_DAYLIGHT 0x01
#define EFI_TIME_IN_DAYLIGHT 0x02
#define EFI_UNSPECIFIED_TIMEZONE 0x07FF

#define EFI_TIME_SIZE 16
struct efi_time {
    unsigned year; // 1900 - 9999
    unsigned char month; // 1 - 12
    unsigned char day; // 1 - 31
    unsigned char hour; // 0 - 23
    unsigned char minute; // 0 - 59
    unsigned char second; // 0 - 59
    unsigned char pad1;
    uint_least32_t nanosecond; // 0 - 999999999
    int_least32_t timezone; // -1440 - 1440, or EFI_UNSPECIFIED_TIMEZONE
    unsigned char daylight;
    unsigned char pad2;
};
void efi_time_read(struct efi_time *self, const unsigned char *in);
void efi_time_write(const struct efi_time *self, unsigned char *out);

// 8.2.3
#define EFI_VARIABLE_AUTHENTICATION_2_SIZE (EFI_TIME_SIZE + WIN_CERTIFICATE_UEFI_GUID_SIZE)
struct efi_variable_authentication_2 {
    struct efi_time timestamp;
    struct win_certificate_uefi_guid auth_info;
};
void efi_variable_authentication_2_read(struct efi_variable_authentication_2 *self, const unsigned char *in);
void efi_variable_authentication_2_write(const struct efi_variable_authentication_2 *self, unsigned char *out);

// 32.4.1
#define EFI_SIGNATURE_DATA_SIZE EFI_GUID_SIZE
struct efi_signature_data {
    struct efi_guid signature_owner;
    // unsigned char signature_data[];
};
void efi_signature_data_read(struct efi_signature_data *self, const unsigned char *in);
void efi_signature_data_write(const struct efi_signature_data *self, unsigned char *out);

#define EFI_SIGNATURE_LIST_SIZE (EFI_GUID_SIZE + 12)
struct efi_signature_list {
    struct efi_guid signature_type;
    uint_least32_t signature_list_size;
    uint_least32_t signature_header_size;
    uint_least32_t signature_size;
    // unsigned char signature_header[signature_header_size];
    // struct efi_signature_data signatures[];
};
void efi_signature_list_read(struct efi_signature_list *self, const unsigned char *in);
void efi_signature_list_write(const struct efi_signature_list *self, unsigned char *out);

#endif
