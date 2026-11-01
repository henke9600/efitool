#include "x.c"

#include "test.h"
#include "x.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static const unsigned char test_store_load_u16_expected[] = { 0x34, 0x12 };

static int test_store_load_u16(void) {
    unsigned char buffer[2];

    x_store_u16(0x1234, &buffer[0]);
    TEST_ASSERT_UINT_ARRAY_EQUALS(buffer, test_store_load_u16_expected)
    TEST_ASSERT_UINT_EQUALS(x_load_u16(&buffer[0]), 0x1234)

    return 0;
}

static const unsigned char test_store_load_u32_expected[] = { 0x78, 0x56, 0x34, 0x12 };

static int test_store_load_u32(void) {
    unsigned char buffer[4];

    x_store_u32(0x12345678, &buffer[0]);
    TEST_ASSERT_UINT_ARRAY_EQUALS(buffer, test_store_load_u32_expected)
    TEST_ASSERT_UINT_EQUALS(x_load_u32(&buffer[0]), 0x12345678)

    return 0;
}

static const int_least32_t test_twos_complement_u16_values[] = { 0, 1, -1, 0x7FFF, -0x8000, 0x1234, -0x1234 };
static const unsigned test_twos_complement_u16_expected[] = { 0, 1, 0xFFFF, 0x7FFF, 0x8000, 0x1234, 0xEDCC };

static int test_twos_complement_u16(void) {
    for (size_t i = 0; i < x_ARRAY_LEN(test_twos_complement_u16_values); ++i) {
        int_least32_t value = test_twos_complement_u16_values[i];
        unsigned twos_complement = x_i32_to_twos_complement_u16(value);
        TEST_ASSERT_UINT_EQUALS(twos_complement, test_twos_complement_u16_expected[i])
        TEST_ASSERT_INT_EQUALS(x_twos_complement_u16_to_i32(twos_complement), value)
    }

    return 0;
}

static int test_twos_complement_u32(void) {
    TEST_ASSERT_UINT_EQUALS(x_i32_to_twos_complement_u32(0), 0)
    TEST_ASSERT_UINT_EQUALS(x_i32_to_twos_complement_u32(1), 1)
    TEST_ASSERT_UINT_EQUALS(x_i32_to_twos_complement_u32(-1), 0xFFFFFFFF)
    TEST_ASSERT_UINT_EQUALS(x_i32_to_twos_complement_u32(0x7FFFFFFF), 0x7FFFFFFF)
    TEST_ASSERT_UINT_EQUALS(x_i32_to_twos_complement_u32(-0x7FFFFFFF), 0x80000001)
    TEST_ASSERT_UINT_EQUALS(x_i32_to_twos_complement_u32(0x12345678), 0x12345678)
    TEST_ASSERT_UINT_EQUALS(x_i32_to_twos_complement_u32(-0x12345678), 0xEDCBA988)

    return 0;
}

int main(void) {
    int failures = 0;
    failures += test_store_load_u16();
    failures += test_store_load_u32();
    failures += test_twos_complement_u16();
    failures += test_twos_complement_u32();

    if (failures == 0) {
        (void)printf("All tests passed!\n");
        return EXIT_SUCCESS;
    }

    (void)printf("%d test(s) failed!\n", failures);
    return EXIT_FAILURE;
}
