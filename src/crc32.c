#include "crc32.h"

#include <stddef.h>
#include <stdint.h>

static uint_least32_t crc32_table[256];

void crc32_init(void) {
    for (int i = 0; i < 256; ++i) {
        uint_least32_t crc = (uint_least32_t)i;
        for (int j = 0; j < 8; ++j) {
            if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320;
            else crc >>= 1;
        }
        crc32_table[i] = crc;
    }
}

void crc32_state_init(struct crc32_state *self) {
    self->crc = 0xFFFFFFFF;
}

void crc32_state_update(struct crc32_state *self, const unsigned char *buffer, size_t size) {
    uint_least32_t crc = self->crc;
    for (size_t i = 0; i < size; ++i) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ buffer[i]) & 0xFF];
    }
    self->crc = crc;
}

uint_least32_t crc32_state_finish(const struct crc32_state *self) {
    return self->crc ^ 0xFFFFFFFF;
}
