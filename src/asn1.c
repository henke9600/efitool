#include "asn1.h"
#include "sha256.h"
#include "x.h"

#include <string.h>
#include <assert.h>
#include <stdint.h>

// "<<<Obsolete>>>"
static const unsigned char asn1_obsolete[] = { 0x3C, 0x3C, 0x3C, 0x4F, 0x62, 0x73, 0x6F, 0x6C, 0x65, 0x74, 0x65, 0x3E, 0x3E, 0x3E };

static const uint_least32_t asn1_pkcs1_rsa_encryption_obj[] = { 1 * 40 + 2, 840, 113549, 1, 1, 1 };
const uint_least32_t asn1_pkcs7_data_obj[] = { 1 * 40 + 2, 840, 113549, 1, 7, 1 };
static const uint_least32_t asn1_pkcs7_signed_data_obj[] = { 1 * 40 + 2, 840, 113549, 1, 7, 2 };
static const uint_least32_t asn1_pkcs9_content_type_obj[] = { 1 * 40 + 2, 840, 113549, 1, 9, 3 };
static const uint_least32_t asn1_pkcs9_message_digest_obj[] = { 1 * 40 + 2, 840, 113549, 1, 9, 4 };
const uint_least32_t asn1_spc_indirect_data_obj[] = { 1 * 40 + 3, 6, 1, 4, 1, 311, 2, 1, 4 };
static const uint_least32_t asn1_spc_pe_image_data_obj[] = { 1 * 40 + 3, 6, 1, 4, 1, 311, 2, 1, 15 };
static const uint_least32_t asn1_sha256_obj[] = { 2 * 40 + 16, 840, 1, 101, 3, 4, 2, 1 };

static size_t asn1_length_octets(size_t payload_size) {
    if (payload_size < 128) return 1;
    size_t n = 1;
    while (payload_size > 0) {
        ++n;
        payload_size >>= 8;
    }
    return n;
}

size_t asn1_size(size_t payload_size) {
    return 1 + asn1_length_octets(payload_size) + payload_size;
}

size_t asn1_write_header(int tag_class, int tag_number, bool constructed, size_t payload_size, unsigned char *out) {
    size_t length_octets = asn1_length_octets(payload_size);
    if (out != NULL) {
        out[0] = (unsigned char)((tag_class << 6) | (constructed ? 0x20 : 0) | tag_number);
        if (length_octets == 1) {
            out[1] = (unsigned char)payload_size;
        } else {
            size_t extra_octets = length_octets - 1;
            out[1] = (unsigned char)(0x80 | extra_octets);
            size_t i = 2 + extra_octets;
            while (i > 2) {
                out[--i] = payload_size & 0xFF;
                payload_size >>= 8;
            }
        }
    }
    return 1 + length_octets;
}

size_t asn1_read_header(
    const unsigned char *in, size_t in_off, size_t in_size,
    int *out_tag_class, int *out_tag_number, bool *out_constructed,
    size_t *out_payload_size
) {
    const unsigned char *pos = in + in_off;
    size_t remaining = in_size - in_off;

    if (remaining < 2) return 0;
    unsigned char tag_octet = pos[0];
    int tag_class = tag_octet >> 6;
    bool constructed = (tag_octet & 0x20) != 0;
    int tag_number = tag_octet & 0x1F;
    if (tag_number == 0x1F) return 0; // Don't support high tag number form

    size_t payload_size;
    size_t header_size;
    unsigned char length_octet = pos[1];
    if (length_octet & 0x80) {
        if (length_octet == 0x80) return 0; // Don't support indefinite length form
        header_size = 2 + (length_octet & 0x7F);
        if (header_size > remaining) return 0;

        payload_size = 0;
        for (size_t i = 2; i < header_size; ++i) {
            if (payload_size > (SIZE_MAX >> 8)) return 0;
            payload_size = (payload_size << 8) | pos[i];
        }
    } else {
        payload_size = length_octet;
        header_size = 2;
    }
    if (payload_size > remaining - header_size) return 0;

    *out_tag_class = tag_class;
    *out_constructed = constructed;
    *out_tag_number = tag_number;
    *out_payload_size = payload_size;
    return header_size;
}

static size_t asn1_integer_payload_size(int_least32_t value) {
    uint_least32_t u = x_i32_to_twos_complement_u32(value);

    unsigned char discard_byte = value < 0 ? 0xFF : 0x00;
    unsigned char ambiguous_msb = value < 0 ? 0x00 : 0x80;
    unsigned char msb = ambiguous_msb; // Initial value accounts for 0 and -1 special cases
    size_t n = 4;
    do {
        unsigned char byte = (u >> ((n - 1) * 8)) & 0xFF;
        if (byte != discard_byte) {
            msb = byte & 0x80;
            break;
        }
    } while (--n > 0);
    if (msb == ambiguous_msb) ++n;
    return n;
}

size_t asn1_integer_write(int_least32_t value, unsigned char *out) {
    uint_least32_t u = x_i32_to_twos_complement_u32(value);

    size_t payload_size = asn1_integer_payload_size(value);
    size_t header_size = asn1_write_header(ASN1_UNIVERSAL, ASN1_INTEGER, false, payload_size, out);
    if (out != NULL) {
        size_t i = header_size + payload_size;
        while (i > header_size) {
            out[--i] = u & 0xFF;
            u >>= 8;
        }
    }
    return header_size + payload_size;
}

static size_t asn1_object_identifier_component_size(uint_least32_t component) {
    if (component == 0) return 1;

    size_t n = 0;
    do {
        ++n;
        component >>= 7;
    } while (component > 0);
    return n;
}

size_t asn1_object_identifier_write(const uint_least32_t *components, size_t component_count, unsigned char *out) {
    size_t payload_size = 0;
    for (size_t i = 0; i < component_count; ++i) {
        payload_size += asn1_object_identifier_component_size(components[i]);
    }

    size_t header_size = asn1_write_header(ASN1_UNIVERSAL, ASN1_OBJECT_IDENTIFIER, false, payload_size, out);
    if (out != NULL) {
        size_t component_start = header_size;
        for (size_t i = 0; i < component_count; ++i) {
            uint_least32_t component = components[i];
            size_t component_size = asn1_object_identifier_component_size(component);

            size_t j = component_start + component_size;
            out[--j] = component & 0x7F;
            while (j > component_start) {
                component >>= 7;
                out[--j] = 0x80 | (component & 0x7F);
            }
            component_start += component_size;
        }
    }
    return header_size + payload_size;
}

size_t asn1_authenticode_spcidc_write(struct asn1_authenticode_spcidc_ctx *ctx, const unsigned char *sha256_hash, unsigned char *out) {
    if (out != NULL) {
        size_t off = 0;
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_SEQUENCE, true, ctx->payload_size, out + off);
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_SEQUENCE, true, ctx->data.payload_size, out + off);
        off += asn1_object_identifier_write(
            &asn1_spc_pe_image_data_obj[0],
            x_ARRAY_LEN(asn1_spc_pe_image_data_obj),
            out + off
        );
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_SEQUENCE, true, ctx->data.value.payload_size, out + off);
        off += asn1_write_header(ASN1_CONTEXT_SPECIFIC, 0, true, ctx->data.value.file.payload_size, out + off);
        off += asn1_write_header(ASN1_CONTEXT_SPECIFIC, 2, true, ctx->data.value.file.file.payload_size, out + off);
        off += asn1_write_header(ASN1_CONTEXT_SPECIFIC, 0, false, sizeof(asn1_obsolete) * 2, out + off);
        for (size_t i = 0; i < sizeof(asn1_obsolete); ++i) {
            out[off++] = 0;
            out[off++] = asn1_obsolete[i];
        }
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_SEQUENCE, true, ctx->message_digest.payload_size, out + off);
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_SEQUENCE, true, ctx->message_digest.digest_algorithm.payload_size, out + off);
        off += asn1_object_identifier_write(&asn1_sha256_obj[0], x_ARRAY_LEN(asn1_sha256_obj), out + off);
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_NULL, false, 0, out + off);
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_OCTET_STRING, false, SHA256_HASH_SIZE, out + off);
        memcpy(out + off, sha256_hash, SHA256_HASH_SIZE);
        off += SHA256_HASH_SIZE;

        assert(off == asn1_size(ctx->payload_size));
        return off;
    }

    ctx->message_digest.digest_algorithm.payload_size = (
        asn1_object_identifier_write(&asn1_sha256_obj[0], x_ARRAY_LEN(asn1_sha256_obj), NULL) +
        asn1_size(0) // NULL
    );
    ctx->message_digest.payload_size = asn1_size(ctx->message_digest.digest_algorithm.payload_size) + asn1_size(SHA256_HASH_SIZE);
    ctx->data.value.file.file.payload_size = asn1_size(sizeof(asn1_obsolete) * 2);
    ctx->data.value.file.payload_size = asn1_size(ctx->data.value.file.file.payload_size);
    ctx->data.value.payload_size = asn1_size(ctx->data.value.file.payload_size);
    ctx->data.payload_size = (
        asn1_object_identifier_write(&asn1_spc_pe_image_data_obj[0], x_ARRAY_LEN(asn1_spc_pe_image_data_obj), NULL) +
        asn1_size(ctx->data.value.payload_size)
    );
    ctx->payload_size = asn1_size(ctx->data.payload_size) + asn1_size(ctx->message_digest.payload_size);
    return asn1_size(ctx->payload_size);
}

size_t asn1_authenticode_auth_attrs_write(
    struct asn1_authenticode_auth_attrs_ctx *ctx,
    const unsigned char *sha256_hash,
    unsigned char *out
) {
    if (out != NULL) {
        size_t off = 0;
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_SET, true, ctx->payload_size, out + off);
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_SEQUENCE, true, ctx->content_type.payload_size, out + off);
        off += asn1_object_identifier_write(&asn1_pkcs9_content_type_obj[0], x_ARRAY_LEN(asn1_pkcs9_content_type_obj), out + off);
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_SET, true, ctx->content_type.value.payload_size, out + off);
        off += asn1_object_identifier_write(&asn1_spc_indirect_data_obj[0], x_ARRAY_LEN(asn1_spc_indirect_data_obj), out + off);
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_SEQUENCE, true, ctx->message_digest.payload_size, out + off);
        off += asn1_object_identifier_write(&asn1_pkcs9_message_digest_obj[0], x_ARRAY_LEN(asn1_pkcs9_message_digest_obj), out + off);
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_SET, true, ctx->message_digest.value.payload_size, out + off);
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_OCTET_STRING, false, SHA256_HASH_SIZE, out + off);
        memcpy(out + off, sha256_hash, SHA256_HASH_SIZE);
        off += SHA256_HASH_SIZE;

        assert(off == asn1_size(ctx->payload_size));
        return off;
    }

    ctx->message_digest.value.payload_size = asn1_size(SHA256_HASH_SIZE);
    ctx->message_digest.payload_size = (
        asn1_object_identifier_write(&asn1_pkcs9_message_digest_obj[0], x_ARRAY_LEN(asn1_pkcs9_message_digest_obj), NULL) +
        asn1_size(ctx->message_digest.value.payload_size)
    );
    ctx->content_type.value.payload_size = asn1_object_identifier_write(
        &asn1_spc_indirect_data_obj[0],
        x_ARRAY_LEN(asn1_spc_indirect_data_obj),
        NULL
    );
    ctx->content_type.payload_size = (
        asn1_object_identifier_write(&asn1_pkcs9_content_type_obj[0], x_ARRAY_LEN(asn1_pkcs9_content_type_obj), NULL) +
        asn1_size(ctx->content_type.value.payload_size)
    );
    ctx->payload_size = asn1_size(ctx->content_type.payload_size) + asn1_size(ctx->message_digest.payload_size);
    return asn1_size(ctx->payload_size);
}

size_t asn1_pkcs7_signed_data_content_info_write(
    struct asn1_pkcs7_signed_data_content_info_ctx *ctx,
    const uint_least32_t *content_obj,
    size_t content_obj_len,
    const unsigned char *content, // May be NULL
    size_t content_size,
    const unsigned char *x509,
    size_t x509_size,
    const unsigned char *issuer,
    size_t issuer_size,
    const unsigned char *serial_number,
    size_t serial_number_size,
    const unsigned char *auth_attrs_payload, // May be NULL
    size_t auth_attrs_payload_size,
    const unsigned char *encrypted_digest,
    size_t encrypted_digest_size,
    unsigned char *out
) {
    int_least32_t signed_data_version = 1;
    int_least32_t signer_info_version = 1;
    if (out != NULL) {
        size_t off = 0;
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_SEQUENCE, true, ctx->payload_size, out + off);
        off += asn1_object_identifier_write(&asn1_pkcs7_signed_data_obj[0], x_ARRAY_LEN(asn1_pkcs7_signed_data_obj), out + off);
        off += asn1_write_header(ASN1_CONTEXT_SPECIFIC, 0, true, ctx->content.payload_size, out + off);
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_SEQUENCE, true, ctx->content._0.payload_size, out + off);
        off += asn1_integer_write(signed_data_version, out + off);
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_SET, true, ctx->content._0.digest_algorithms.payload_size, out + off);
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_SEQUENCE, true, ctx->content._0.digest_algorithms.sha256.payload_size, out + off);
        off += asn1_object_identifier_write(&asn1_sha256_obj[0], x_ARRAY_LEN(asn1_sha256_obj), out + off);
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_NULL, false, 0, out + off);
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_SEQUENCE, true, ctx->content._0.content_info.payload_size, out + off);
        off += asn1_object_identifier_write(content_obj, content_obj_len, out + off);
        if (content != NULL) {
            off += asn1_write_header(ASN1_CONTEXT_SPECIFIC, 0, true, content_size, out + off);
            memcpy(out + off, content, content_size);
            off += content_size;
        }
        off += asn1_write_header(ASN1_CONTEXT_SPECIFIC, 0, true, x509_size, out + off);
        memcpy(out + off, x509, x509_size);
        off += x509_size;
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_SET, true, ctx->content._0.signer_infos.payload_size, out + off);
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_SEQUENCE, true, ctx->content._0.signer_infos.signer_info.payload_size, out + off);
        off += asn1_integer_write(signer_info_version, out + off);
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_SEQUENCE, true, issuer_size + serial_number_size, out + off);
        memcpy(out + off, issuer, issuer_size);
        off += issuer_size;
        memcpy(out + off, serial_number, serial_number_size);
        off += serial_number_size;
        off += asn1_write_header(
            ASN1_UNIVERSAL, ASN1_SEQUENCE, true,
            ctx->content._0.signer_infos.signer_info.digest_algorithm.payload_size,
            out + off
        );
        off += asn1_object_identifier_write(&asn1_sha256_obj[0], x_ARRAY_LEN(asn1_sha256_obj), out + off);
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_NULL, false, 0, out + off);
        if (auth_attrs_payload != NULL) {
            off += asn1_write_header(ASN1_CONTEXT_SPECIFIC, 0, true, auth_attrs_payload_size, out + off);
            memcpy(out + off, auth_attrs_payload, auth_attrs_payload_size);
            off += auth_attrs_payload_size;
        }
        off += asn1_write_header(
            ASN1_UNIVERSAL, ASN1_SEQUENCE, true,
            ctx->content._0.signer_infos.signer_info.digest_encryption_algorithm.payload_size,
            out + off
        );
        off += asn1_object_identifier_write(&asn1_pkcs1_rsa_encryption_obj[0], x_ARRAY_LEN(asn1_pkcs1_rsa_encryption_obj), out + off);
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_NULL, false, 0, out + off);
        off += asn1_write_header(ASN1_UNIVERSAL, ASN1_OCTET_STRING, false, encrypted_digest_size, out + off);
        memcpy(out + off, encrypted_digest, encrypted_digest_size);
        off += encrypted_digest_size;

        assert(off == asn1_size(ctx->payload_size));
        return off;
    }

    ctx->content._0.signer_infos.signer_info.digest_encryption_algorithm.payload_size = (
        asn1_object_identifier_write(&asn1_pkcs1_rsa_encryption_obj[0], x_ARRAY_LEN(asn1_pkcs1_rsa_encryption_obj), NULL) +
        asn1_size(0)
    );
    ctx->content._0.signer_infos.signer_info.digest_algorithm.payload_size = (
        asn1_object_identifier_write(&asn1_sha256_obj[0], x_ARRAY_LEN(asn1_sha256_obj), NULL) +
        asn1_size(0)
    );
    ctx->content._0.signer_infos.signer_info.payload_size = (
        asn1_integer_write(signer_info_version, NULL) +
        asn1_size(issuer_size + serial_number_size) +
        asn1_size(ctx->content._0.signer_infos.signer_info.digest_algorithm.payload_size) +
        asn1_size(ctx->content._0.signer_infos.signer_info.digest_encryption_algorithm.payload_size) +
        asn1_size(encrypted_digest_size)
    );
    if (auth_attrs_payload != NULL) ctx->content._0.signer_infos.signer_info.payload_size += asn1_size(auth_attrs_payload_size);
    ctx->content._0.signer_infos.payload_size = asn1_size(ctx->content._0.signer_infos.signer_info.payload_size);
    ctx->content._0.content_info.payload_size = asn1_object_identifier_write(content_obj, content_obj_len, NULL);
    if (content != NULL) ctx->content._0.content_info.payload_size += asn1_size(content_size);
    ctx->content._0.digest_algorithms.sha256.payload_size = (
        asn1_object_identifier_write(&asn1_sha256_obj[0], x_ARRAY_LEN(asn1_sha256_obj), NULL) +
        asn1_size(0)
    );
    ctx->content._0.digest_algorithms.payload_size = asn1_size(ctx->content._0.digest_algorithms.sha256.payload_size);
    ctx->content._0.payload_size = (
        asn1_integer_write(signed_data_version, NULL) +
        asn1_size(ctx->content._0.digest_algorithms.payload_size) +
        asn1_size(ctx->content._0.content_info.payload_size) +
        asn1_size(x509_size) +
        asn1_size(ctx->content._0.signer_infos.payload_size)
    );
    ctx->content.payload_size = asn1_size(ctx->content._0.payload_size);
    ctx->payload_size = (
        asn1_object_identifier_write(&asn1_pkcs7_signed_data_obj[0], x_ARRAY_LEN(asn1_pkcs7_signed_data_obj), NULL) +
        asn1_size(ctx->content.payload_size)
    );
    return asn1_size(ctx->payload_size);
}

int asn1_parse_pkcs7_signed_data_content_info(
    const unsigned char *in,
    size_t in_size,
    const unsigned char **out_x509,
    size_t *out_x509_size,
    const unsigned char **out_encrypted_digest,
    size_t *out_encrypted_digest_size
) {
    int class;
    int tag;
    bool constructed;
    size_t payload_size;
    size_t header_size;
    size_t off = 0;

    header_size = asn1_read_header(in, off, in_size, &class, &tag, &constructed, &payload_size);
    if (header_size == 0 || class != ASN1_UNIVERSAL || tag != ASN1_SEQUENCE || constructed != true) return -1;
    off += header_size;
    size_t outer_payload_end = off + payload_size;

    // contentType
    header_size = asn1_read_header(in, off, outer_payload_end, &class, &tag, &constructed, &payload_size);
    if (header_size == 0 || class != ASN1_UNIVERSAL || tag != ASN1_OBJECT_IDENTIFIER || constructed != false) return -1;
    off += header_size + payload_size;

    // content
    header_size = asn1_read_header(in, off, outer_payload_end, &class, &tag, &constructed, &payload_size);
    if (header_size == 0 || class != ASN1_CONTEXT_SPECIFIC || tag != 0 || constructed != true) return -1;
    off += header_size;
    size_t content_payload_end = off + payload_size;

    // content 0
    header_size = asn1_read_header(in, off, content_payload_end, &class, &tag, &constructed, &payload_size);
    if (header_size == 0 || class != ASN1_UNIVERSAL || tag != ASN1_SEQUENCE || constructed != true) return -1;
    off += header_size;
    size_t content_0_payload_end = off + payload_size;

    // version
    header_size = asn1_read_header(in, off, content_0_payload_end, &class, &tag, &constructed, &payload_size);
    if (header_size == 0 || class != ASN1_UNIVERSAL || tag != ASN1_INTEGER || constructed != false) return -1;
    off += header_size + payload_size;

    // digestAlgorithms
    header_size = asn1_read_header(in, off, content_0_payload_end, &class, &tag, &constructed, &payload_size);
    if (header_size == 0 || class != ASN1_UNIVERSAL || tag != ASN1_SET || constructed != true) return -1;
    off += header_size + payload_size;

    // contentInfo
    header_size = asn1_read_header(in, off, content_0_payload_end, &class, &tag, &constructed, &payload_size);
    if (header_size == 0 || class != ASN1_UNIVERSAL || tag != ASN1_SEQUENCE || constructed != true) return -1;
    off += header_size + payload_size;

    // certificates
    header_size = asn1_read_header(in, off, content_0_payload_end, &class, &tag, &constructed, &payload_size);
    if (header_size == 0 || class != ASN1_CONTEXT_SPECIFIC || tag != 0 || constructed != true) return -1;
    off += header_size;
    const unsigned char *x509 = in + off;
    size_t x509_size = payload_size;
    off += payload_size;

    // signerInfos (or crls, but don't support that)
    header_size = asn1_read_header(in, off, content_0_payload_end, &class, &tag, &constructed, &payload_size);
    if (header_size == 0 || class != ASN1_UNIVERSAL || tag != ASN1_SET || constructed != true) return -1;
    off += header_size;
    size_t signer_infos_end = off + payload_size;

    header_size = asn1_read_header(in, off, signer_infos_end, &class, &tag, &constructed, &payload_size);
    if (header_size == 0 || class != ASN1_UNIVERSAL || tag != ASN1_SEQUENCE || constructed != true) return -1;
    off += header_size;
    size_t signer_info_end = off + payload_size;
    if (signer_info_end != signer_infos_end) return -1; // More than one signer info

    // version
    header_size = asn1_read_header(in, off, signer_info_end, &class, &tag, &constructed, &payload_size);
    if (header_size == 0 || class != ASN1_UNIVERSAL || tag != ASN1_INTEGER || constructed != false) return -1;
    off += header_size + payload_size;

    // issuerAndSerialNumber
    header_size = asn1_read_header(in, off, signer_info_end, &class, &tag, &constructed, &payload_size);
    if (header_size == 0 || class != ASN1_UNIVERSAL || tag != ASN1_SEQUENCE || constructed != true) return -1;
    off += header_size + payload_size;

    // digestAlgorithm
    header_size = asn1_read_header(in, off, signer_info_end, &class, &tag, &constructed, &payload_size);
    if (header_size == 0 || class != ASN1_UNIVERSAL || tag != ASN1_SEQUENCE || constructed != true) return -1;
    off += header_size + payload_size;

    // digestEncryptionAlgorithm
    header_size = asn1_read_header(in, off, signer_info_end, &class, &tag, &constructed, &payload_size);
    if (header_size == 0 || class != ASN1_UNIVERSAL || tag != ASN1_SEQUENCE || constructed != true) return -1;
    off += header_size + payload_size;

    // encryptedDigest
    header_size = asn1_read_header(in, off, signer_info_end, &class, &tag, &constructed, &payload_size);
    if (header_size == 0 || class != ASN1_UNIVERSAL || tag != ASN1_OCTET_STRING || constructed != false) return -1;
    off += header_size;
    if (off + payload_size != signer_info_end) return -1;

    *out_x509 = x509;
    *out_x509_size = x509_size;
    *out_encrypted_digest = in + off;
    *out_encrypted_digest_size = payload_size;
    return 0;
}

int asn1_parse_x509(
    const unsigned char *in,
    size_t in_size,
    const unsigned char **out_serial_number,
    size_t *out_serial_number_size,
    const unsigned char **out_issuer,
    size_t *out_issuer_size
) {
    int class;
    int tag;
    bool constructed;
    size_t payload_size;
    size_t header_size;
    size_t off = 0;

    header_size = asn1_read_header(in, off, in_size, &class, &tag, &constructed, &payload_size);
    if (header_size == 0 || class != ASN1_UNIVERSAL || tag != ASN1_SEQUENCE || constructed != true) return -1;
    off += header_size;
    size_t outer_payload_end = off + payload_size;

    // tbsCertificate
    header_size = asn1_read_header(in, off, outer_payload_end, &class, &tag, &constructed, &payload_size);
    if (header_size == 0 || class != ASN1_UNIVERSAL || tag != ASN1_SEQUENCE || constructed != true) return -1;
    off += header_size;
    size_t tbs_certificate_end = off + payload_size;

    // version or serialNumber
    header_size = asn1_read_header(in, off, tbs_certificate_end, &class, &tag, &constructed, &payload_size);
    if (header_size == 0) return -1;
    if (class == ASN1_CONTEXT_SPECIFIC && tag == 0 && constructed == true) {
        // It was version, skip over it
        off += header_size + payload_size;
        // serialNumber
        header_size = asn1_read_header(in, off, tbs_certificate_end, &class, &tag, &constructed, &payload_size);
    }
    if (header_size == 0 || class != ASN1_UNIVERSAL || tag != ASN1_INTEGER || constructed != false) return -1;
    const unsigned char *serial_number = in + off;
    size_t serial_number_size = header_size + payload_size;
    off += serial_number_size;

    // signature
    header_size = asn1_read_header(in, off, tbs_certificate_end, &class, &tag, &constructed, &payload_size);
    if (header_size == 0 || class != ASN1_UNIVERSAL || tag != ASN1_SEQUENCE || constructed != true) return -1;
    off += header_size + payload_size;

    // issuer
    header_size = asn1_read_header(in, off, tbs_certificate_end, &class, &tag, &constructed, &payload_size);
    if (header_size == 0 || class != ASN1_UNIVERSAL || tag != ASN1_SEQUENCE || constructed != true) return -1;

    *out_serial_number = serial_number;
    *out_serial_number_size = serial_number_size;
    *out_issuer = in + off;
    *out_issuer_size = header_size + payload_size;
    return 0;
}
