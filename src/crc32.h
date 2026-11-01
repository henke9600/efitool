#ifndef CRC32_H
#define CRC32_H

#include <stdint.h>
#include <stddef.h>

struct crc32_state {
    uint_least32_t crc;
};

void crc32_init(void);

void crc32_state_init(struct crc32_state *self);
void crc32_state_update(struct crc32_state *self, const unsigned char *buffer, size_t size);
uint_least32_t crc32_state_finish(const struct crc32_state *self);

#endif
