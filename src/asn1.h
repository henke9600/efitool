#ifndef ASN1_H
#define ASN1_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

// Tag classes
#define ASN1_UNIVERSAL 0
#define ASN1_APPLICATION 1
#define ASN1_CONTEXT_SPECIFIC 2
#define ASN1_PRIVATE 3

// Universal tag numbers
#define ASN1_INTEGER 2
#define ASN1_BIT_STRING 3
#define ASN1_OCTET_STRING 4
#define ASN1_NULL 5
#define ASN1_OBJECT_IDENTIFIER 6
#define ASN1_SEQUENCE 16
#define ASN1_SET 17

size_t asn1_size(size_t payload_size);
size_t asn1_write_header(int tag_class, int tag_number, bool constructed, size_t payload_size, unsigned char *out);
// Returns 0 on error
size_t asn1_read_header(
    unsigned char *in, size_t in_off, size_t in_size,
    int *out_tag_class, int *out_tag_number, bool *out_constructed, size_t *out_payload_size
);

size_t asn1_integer_write(int_least32_t value, unsigned char *out);

size_t asn1_object_identifier_write(uint_least32_t *components, size_t component_count, unsigned char *out);

// SpcIndirectDataContent
struct asn1_authenticode_spcidc_ctx {
    size_t payload_size;
    struct {
        size_t payload_size;
        struct {
            size_t payload_size;
            struct {
                size_t payload_size;
                struct {
                    size_t payload_size;
                } file;
            } file;
        } value;
    } data;
    struct {
        size_t payload_size;
        struct {
            size_t payload_size;
        } digest_algorithm;
    } message_digest;
};
size_t asn1_authenticode_spcidc_write(struct asn1_authenticode_spcidc_ctx *ctx, unsigned char *sha256_hash, unsigned char *out);

struct asn1_authenticode_auth_attrs_ctx {
    size_t payload_size;
    struct {
        size_t payload_size;
        struct {
            size_t payload_size;
        } value;
    } content_type;
    struct {
        size_t payload_size;
        struct {
            size_t payload_size;
        } value;
    } message_digest;
};
size_t asn1_authenticode_auth_attrs_write(struct asn1_authenticode_auth_attrs_ctx *ctx, unsigned char *sha256_hash, unsigned char *out);

struct asn1_pkcs7_signed_data_content_info_ctx {
    size_t payload_size;
    struct {
        size_t payload_size;
        struct {
            size_t payload_size;
            struct {
                size_t payload_size;
                struct {
                    size_t payload_size;
                } sha256;
            } digest_algorithms;
            struct {
                size_t payload_size;
            } content_info;
            struct {
                size_t payload_size;
                struct {
                    size_t payload_size;
                    struct {
                        size_t payload_size;
                    } digest_algorithm;
                    struct {
                        size_t payload_size;
                    } digest_encryption_algorithm;
                } signer_info;
            } signer_infos;
        } _0;
    } content;
};

size_t asn1_pkcs7_signed_data_content_info_write(
    struct asn1_pkcs7_signed_data_content_info_ctx *ctx,
    uint_least32_t *content_obj,
    size_t content_obj_len,
    unsigned char *content, // May be NULL
    size_t content_size,
    unsigned char *x509,
    size_t x509_size,
    unsigned char *issuer,
    size_t issuer_size,
    unsigned char *serial_number,
    size_t serial_number_size,
    unsigned char *auth_attrs_payload, // May be NULL
    size_t auth_attrs_payload_size,
    unsigned char *encrypted_digest,
    size_t encrypted_digest_size,
    unsigned char *out
);

int asn1_parse_pkcs7_signed_data_content_info(
    unsigned char *in,
    size_t in_size,
    unsigned char **out_x509,
    size_t *out_x509_size,
    unsigned char **out_encrypted_digest,
    size_t *out_encrypted_digest_size
);

int asn1_parse_x509(
    unsigned char *in,
    size_t in_size,
    unsigned char **out_serial_number,
    size_t *out_serial_number_size,
    unsigned char **out_issuer,
    size_t *out_issuer_size
);

#endif
