#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_HASH_SIZE 32
#define SHA256_BLOCK_SIZE 64

struct sha256 {
    uint_least32_t state[8];
    uint_least32_t block_count0;
    uint_least32_t block_count1;
    unsigned char buffer[SHA256_BLOCK_SIZE];
    unsigned buffer_size;
};

void sha256_init(struct sha256 *self);
void sha256_update(struct sha256 *self, unsigned char *in, size_t size);
void sha256_finish(struct sha256 *self, unsigned char *hash);

#endif
