#include "efi.h"
#include "x.h"

#include <stdint.h>
#include <string.h>

const struct efi_guid efi_cert_type_pkcs7_guid = { 0x4AAFD29D, 0x68DF, 0x49EE, { 0x8A, 0xA9, 0x34, 0x7D, 0x37, 0x56, 0x65, 0xA7 } };

void efi_guid_read(struct efi_guid *self, unsigned char *in) {
    self->data1 = x_load_u32(in);
    self->data2 = x_load_u16(in + 4);
    self->data3 = x_load_u16(in + 6);
    memcpy(&self->data4[0], in + 8, 8);
}
void efi_guid_write(struct efi_guid *self, unsigned char *out) {
    x_store_u32(self->data1, out);
    x_store_u16(self->data2, out + 4);
    x_store_u16(self->data3, out + 6);
    memcpy(out + 8, &self->data4[0], 8);
}
bool efi_guid_equals(struct efi_guid *self, struct efi_guid *other) {
    if (self->data1 != other->data1) return false;
    if (self->data2 != other->data2) return false;
    if (self->data3 != other->data3) return false;
    return memcmp(&self->data4[0], &other->data4[0], sizeof(self->data4)) == 0;
}

void win_certificate_read(struct win_certificate *self, unsigned char *in) {
    self->length = x_load_u32(in);
    self->revision = x_load_u16(in + 4);
    self->certificate_type = x_load_u16(in + 6);
}
void win_certificate_write(struct win_certificate *self, unsigned char *out) {
    x_store_u32(self->length, out);
    x_store_u16(self->revision, out + 4);
    x_store_u16(self->certificate_type, out + 6);
}

void win_certificate_uefi_guid_read(struct win_certificate_uefi_guid *self, unsigned char *in) {
    win_certificate_read(&self->hdr, in);
    efi_guid_read(&self->cert_type, in + WIN_CERTIFICATE_SIZE);
}
void win_certificate_uefi_guid_write(struct win_certificate_uefi_guid *self, unsigned char *out) {
    win_certificate_write(&self->hdr, out);
    efi_guid_write(&self->cert_type, out + WIN_CERTIFICATE_SIZE);
}

void efi_time_read(struct efi_time *self, unsigned char *in) {
    self->year = x_load_u16(in);
    self->month = in[2];
    self->day = in[3];
    self->hour = in[4];
    self->minute = in[5];
    self->second = in[6];
    self->pad1 = in[7];
    self->nanosecond = x_load_u32(in + 8);
    self->timezone = x_twos_complement_u16_to_i32(x_load_u16(in + 12));
    self->daylight = in[14];
    self->pad2 = in[15];
}
void efi_time_write(struct efi_time *self, unsigned char *out) {
    x_store_u16(self->year, out);
    out[2] = self->month;
    out[3] = self->day;
    out[4] = self->hour;
    out[5] = self->minute;
    out[6] = self->second;
    out[7] = self->pad1;
    x_store_u32(self->nanosecond, out + 8);
    x_store_u16(x_i32_to_twos_complement_u16(self->timezone), out + 12);
    out[14] = self->daylight;
    out[15] = self->pad2;
}

void efi_variable_authentication_2_read(struct efi_variable_authentication_2 *self, unsigned char *in) {
    efi_time_read(&self->timestamp, in);
    win_certificate_uefi_guid_read(&self->auth_info, in + EFI_TIME_SIZE);
}
void efi_variable_authentication_2_write(struct efi_variable_authentication_2 *self, unsigned char *out) {
    efi_time_write(&self->timestamp, out);
    win_certificate_uefi_guid_write(&self->auth_info, out + EFI_TIME_SIZE);
}

void efi_signature_data_read(struct efi_signature_data *self, unsigned char *in) {
    efi_guid_read(&self->signature_owner, in);
}
void efi_signature_data_write(struct efi_signature_data *self, unsigned char *out) {
    efi_guid_write(&self->signature_owner, out);
}

void efi_signature_list_read(struct efi_signature_list *self, unsigned char *in) {
    efi_guid_read(&self->signature_type, in);
    self->signature_list_size = x_load_u32(in + EFI_GUID_SIZE);
    self->signature_header_size = x_load_u32(in + EFI_GUID_SIZE + 4);
    self->signature_size = x_load_u32(in + EFI_GUID_SIZE + 8);
}
void efi_signature_list_write(struct efi_signature_list *self, unsigned char *out) {
    efi_guid_write(&self->signature_type, out);
    x_store_u32(self->signature_list_size, out + EFI_GUID_SIZE);
    x_store_u32(self->signature_header_size, out + EFI_GUID_SIZE + 4);
    x_store_u32(self->signature_size, out + EFI_GUID_SIZE + 8);
}
