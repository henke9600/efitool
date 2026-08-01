// Based on public domain code by D. J. Bernstein
#include "sha256.h"

#include <string.h>
#include <stdint.h>

#define SHA256_BLOCK_SHIFT 6
#define SHA256_BLOCK_MASK 63

#define SHA256_ROTR(X, N) ((((X) & 0xFFFFFFFF) >> (N)) | ((X) << (32 - (N))))

#define SHA256_SIGMA0_A(X) (SHA256_ROTR(X, 7) ^ SHA256_ROTR(X, 18) ^ (((X) & 0xFFFFFFFF) >> 3))
#define SHA256_SIGMA1_A(X) (SHA256_ROTR(X, 17) ^ SHA256_ROTR(X, 19) ^ (((X) & 0xFFFFFFFF) >> 10))

#define SHA256_CH(X, Y, Z) ((Z) ^ ((X) & ((Y) ^ (Z))))
#define SHA256_MAJ(X, Y, Z) (((X) & ((Y) ^ (Z))) ^ ((Y) & (Z)))
#define SHA256_SIGMA0_B(X) (SHA256_ROTR(X, 2) ^ SHA256_ROTR(X, 13) ^ SHA256_ROTR(X, 22))
#define SHA256_SIGMA1_B(X) (SHA256_ROTR(X, 6) ^ SHA256_ROTR(X, 11) ^ SHA256_ROTR(X, 25))

static const uint_least32_t sha256_round[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

static void sha256_block(uint_least32_t *state, unsigned char *in) {
    uint_least32_t w[64];
    uint_least32_t r[72];

    for (int i = 0; i < 8; ++i) r[7 - i] = state[i];
    for (size_t i = 0; i < 16; ++i) {
        unsigned char *x = in + i * 4;
        w[i] = (
            ((uint_least32_t)x[0] << 24) |
            ((uint_least32_t)x[1] << 16) |
            ((uint_least32_t)x[2] << 8) |
            (uint_least32_t)x[3]
        );
    }

    for (int i = 0;; ++i) {
        uint_least32_t x = r[i] + w[i] + sha256_round[i] + SHA256_SIGMA1_B(r[i + 3]) + SHA256_CH(r[i + 3], r[i + 2], r[i + 1]);
        r[i + 4] += x;
        r[i + 8] = x + SHA256_SIGMA0_B(r[i + 7]) + SHA256_MAJ(r[i + 7], r[i + 6], r[i + 5]);

        if (i < 48) w[i + 16] = w[i] + w[i + 9] + SHA256_SIGMA1_A(w[i + 14]) + SHA256_SIGMA0_A(w[i + 1]);
        else if (i == 63) break;
    }

    for (int i = 0; i < 8; ++i) state[i] += r[71 - i];
}

void sha256_init(struct sha256 *self) {
    self->state[0] = 0x6A09E667;
    self->state[1] = 0xBB67AE85;
    self->state[2] = 0x3C6EF372;
    self->state[3] = 0xA54FF53A;
    self->state[4] = 0x510E527F;
    self->state[5] = 0x9B05688C;
    self->state[6] = 0x1F83D9AB;
    self->state[7] = 0x5BE0CD19;
    self->block_count0 = 0;
    self->block_count1 = 0;
    self->buffer_size = 0;
}

void sha256_update(struct sha256 *self, unsigned char *in, size_t size) {
    if (self->buffer_size > 0) {
        unsigned num_to_read = SHA256_BLOCK_SIZE - self->buffer_size;
        if (num_to_read > size) num_to_read = (unsigned)size;
        memcpy(&self->buffer[self->buffer_size], in, num_to_read);
        self->buffer_size += num_to_read;
        if (self->buffer_size < SHA256_BLOCK_SIZE) return;
        sha256_block(&self->state[0], &self->buffer[0]);
        if ((++self->block_count0 & 0xFFFFFFFF) == 0) ++self->block_count1;
        in += num_to_read;
        size -= num_to_read;
    }
    size_t num_blocks = size >> SHA256_BLOCK_SHIFT;
    for (size_t i = 0; i < num_blocks; ++i) {
        sha256_block(&self->state[0], in + i * SHA256_BLOCK_SIZE);
        if ((++self->block_count0 & 0xFFFFFFFF) == 0) ++self->block_count1;
    }

    self->buffer_size = size & SHA256_BLOCK_MASK;
    if (self->buffer_size > 0) {
        memcpy(&self->buffer[0], in + (size - self->buffer_size), self->buffer_size);
    }
}

void sha256_finish(struct sha256 *self, unsigned char *hash) {
    unsigned byte_count = self->buffer_size;

    self->buffer[self->buffer_size++] = 0x80;
    if (self->buffer_size > 56) {
        memset(&self->buffer[self->buffer_size], 0, 64 - self->buffer_size);
        sha256_block(&self->state[0], &self->buffer[0]);
        self->buffer_size = 0;
    }

    memset(&self->buffer[self->buffer_size], 0, 56 - self->buffer_size);
    self->buffer[56] = (self->block_count1 >> 15) & 0xFF;
    self->buffer[57] = (self->block_count1 >> 7) & 0xFF;
    self->buffer[58] = ((self->block_count1 << 1) | (self->block_count0 >> 31)) & 0xFF;
    self->buffer[59] = (self->block_count0 >> 23) & 0xFF;
    self->buffer[60] = (self->block_count0 >> 15) & 0xFF;
    self->buffer[61] = (self->block_count0 >> 7) & 0xFF;
    self->buffer[62] = ((self->block_count0 << 1) | (byte_count >> 5)) & 0xFF;
    self->buffer[63] = (byte_count << 3) & 0xFF;

    sha256_block(&self->state[0], &self->buffer[0]);
    for (size_t i = 0; i < 8; ++i) {
        uint_least32_t state = self->state[i];
        unsigned char *dest = hash + i * 4;
        dest[0] = (unsigned char)((state >> 24) & 0xFF);
        dest[1] = (unsigned char)((state >> 16) & 0xFF);
        dest[2] = (unsigned char)((state >> 8) & 0xFF);
        dest[3] = (unsigned char)(state & 0xFF);
    }
}
