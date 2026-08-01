#ifndef X_H
#define X_H

#include <stdint.h>

#define x_STR(X) #X
#define x_XSTR(X) x_STR(X)
#define x_ARRAY_LEN(ARRAY) (sizeof(ARRAY) / sizeof((ARRAY)[0]))
#define x_ARRAY_END(ARRAY) (&(ARRAY)[x_ARRAY_LEN(ARRAY) - 1] + 1)
#define x_STR_LEN(STR) (x_ARRAY_LEN(STR) - 1)

#if (SIZE_MAX / 2) < 0x7FFFFFFF
#define x_SAFE_SIZE (SIZE_MAX / 2)
#else
#define x_SAFE_SIZE 0x7FFFFFFF
#endif

unsigned x_load_u16(unsigned char *in);
void x_store_u16(unsigned in, unsigned char *out);
uint_least32_t x_load_u32(unsigned char *in);
void x_store_u32(uint_least32_t in, unsigned char *out);

int_least32_t x_twos_complement_u16_to_i32(unsigned in);
unsigned x_i32_to_twos_complement_u16(int_least32_t in);
uint_least32_t x_i32_to_twos_complement_u32(int_least32_t in);

#endif
