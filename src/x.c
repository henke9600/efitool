#include "x.h"

#include <stdint.h>

unsigned x_load_u16(unsigned char *in) {
    return (
        (unsigned)in[0] |
        ((unsigned)in[1] << 8)
    );
}

void x_store_u16(unsigned in, unsigned char *out) {
    out[0] = (unsigned char)(in & 0xFF);
    out[1] = (unsigned char)((in >> 8) & 0xFF);
}

uint_least32_t x_load_u32(unsigned char *in) {
    return (
        (uint_least32_t)in[0] |
        ((uint_least32_t)in[1] << 8) |
        ((uint_least32_t)in[2] << 16) |
        ((uint_least32_t)in[3] << 24)
    );
}

void x_store_u32(uint_least32_t in, unsigned char *out) {
    out[0] = (unsigned char)(in & 0xFF);
    out[1] = (unsigned char)((in >> 8) & 0xFF);
    out[2] = (unsigned char)((in >> 16) & 0xFF);
    out[3] = (unsigned char)((in >> 24) & 0xFF);
}

int_least32_t x_twos_complement_u16_to_i32(unsigned in) {
    if (in <= 0x7FFF) return (int_least32_t)in;
    return (int_least32_t)(in - 0x7FFF - 1) - 0x7FFF - 1;
}

unsigned x_i32_to_twos_complement_u16(int_least32_t in) {
    if (in >= 0) return (unsigned)in;
    return (unsigned)(in + 0x7FFF + 1) + 0x7FFF + 1;
}

uint_least32_t x_i32_to_twos_complement_u32(int_least32_t in) {
    if (in >= 0) return (uint_least32_t)in;
    return (uint_least32_t)(in + 0x7FFFFFFF + 1) + 0x7FFFFFFF + 1;
}
