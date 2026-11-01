#include "sha256.c"

#include "test.h"
#include "sha256.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char test_empty_expected[] = {
    0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
    0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55
};

static int test_empty(void) {
    unsigned char hash[SHA256_HASH_SIZE];

    struct sha256 sha256;
    sha256_init(&sha256);
    sha256_update(&sha256, NULL, 0);
    sha256_finish(&sha256, &hash[0]);
    TEST_ASSERT_UINT_ARRAY_EQUALS(hash, test_empty_expected);

    return 0;
}

static const unsigned char test_abc_input[] = { 97, 98, 99 }; // "abc"
static const unsigned char test_abc_expected[] = {
    0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
    0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
};

static int test_abc(void) {
    unsigned char hash[SHA256_HASH_SIZE];

    struct sha256 sha256;
    sha256_init(&sha256);
    sha256_update(&sha256, &test_abc_input[0], sizeof(test_abc_input));
    sha256_finish(&sha256, &hash[0]);
    TEST_ASSERT_UINT_ARRAY_EQUALS(hash, test_abc_expected)

    return 0;
}

static const unsigned char test_5000x200_a_expected[SHA256_HASH_SIZE] = {
    0xCD, 0xC7, 0x6E, 0x5C, 0x99, 0x14, 0xFB, 0x92, 0x81, 0xA1, 0xC7, 0xE2, 0x84, 0xD7, 0x3E, 0x67,
    0xF1, 0x80, 0x9A, 0x48, 0xA4, 0x97, 0x20, 0x0E, 0x04, 0x6D, 0x39, 0xCC, 0xC7, 0x11, 0x2C, 0xD0
};

static int test_5000x200_a(void) {
    unsigned char hash[SHA256_HASH_SIZE];
    unsigned char input[200];
    memset(&input[0], 97, sizeof(input)); // 'a' repeated

    struct sha256 sha256;
    sha256_init(&sha256);
    for (size_t i = 0; i < 5000; ++i) sha256_update(&sha256, &input[0], sizeof(input));
    sha256_finish(&sha256, &hash[0]);
    TEST_ASSERT_UINT_ARRAY_EQUALS(hash, test_5000x200_a_expected)

    return 0;
}

int main(void) {
    int failures = 0;
    failures += test_empty();
    failures += test_abc();
    failures += test_5000x200_a();

    if (failures == 0) {
        (void)printf("All tests passed!\n");
        return EXIT_SUCCESS;
    }

    (void)printf("%d test(s) failed!\n", failures);
    return EXIT_FAILURE;
}
