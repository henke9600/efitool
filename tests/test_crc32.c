#include "crc32.c"

#include "test.h"
#include "crc32.h"

#include <stdio.h>
#include <stdlib.h>

static int test_empty(void) {
    struct crc32_state state;
    crc32_state_init(&state);
    TEST_ASSERT_UINT_EQUALS(crc32_state_finish(&state), 0x00000000)

    crc32_state_update(&state, NULL, 0);
    TEST_ASSERT_UINT_EQUALS(crc32_state_finish(&state), 0x00000000)

    return 0;
}

static int test_123456789(void) {
    unsigned char input[9];
    for (unsigned char i = 0; i < 9; ++i) input[i] = 49 + i;

    struct crc32_state state;
    crc32_state_init(&state);
    crc32_state_update(&state, &input[0], sizeof(input));
    TEST_ASSERT_UINT_EQUALS(crc32_state_finish(&state), 0xCBF43926)

    return 0;
}

static int test_123456789_incremental(void) {
    unsigned char input[9];
    for (unsigned char i = 0; i < 9; ++i) input[i] = 49 + i;

    struct crc32_state state;
    crc32_state_init(&state);
    crc32_state_update(&state, &input[0], 0);
    crc32_state_update(&state, &input[0], 1);
    crc32_state_update(&state, &input[1], 2);
    TEST_ASSERT_UINT_EQUALS(crc32_state_finish(&state), 0x884863D2) // "123"
    crc32_state_update(&state, &input[3], 3);
    crc32_state_update(&state, &input[6], 2);
    crc32_state_update(&state, &input[8], 1);
    crc32_state_update(&state, &input[9], 0);
    TEST_ASSERT_UINT_EQUALS(crc32_state_finish(&state), 0xCBF43926)

    return 0;
}

int main(void) {
    crc32_init();

    int failures = 0;
    failures += test_empty();
    failures += test_123456789();
    failures += test_123456789_incremental();

    if (failures == 0) {
        (void)printf("All tests passed!\n");
        return EXIT_SUCCESS;
    }

    (void)printf("%d test(s) failed!\n", failures);
    return EXIT_FAILURE;
}
