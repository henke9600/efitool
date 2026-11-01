#ifndef TEST_H
#define TEST_H

#include <stddef.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>

#define TEST_ASSERT(CONDITION) \
    if (!(CONDITION)) { \
        (void)printf("FAIL: %s:%d\n", __FILE__, __LINE__); \
        return 1; \
    }

#define TEST_ASSERT_INT_EQUALS(A, B) \
    { \
        int_least32_t a = (int_least32_t)(A); \
        int_least32_t b = (int_least32_t)(B); \
        if (a != b) { \
            (void)printf("FAIL: %s:%d: %" PRIiLEAST32 " != %" PRIiLEAST32 "\n", __FILE__, __LINE__, a, b); \
            return 1; \
        } \
    }

#define TEST_ASSERT_UINT_EQUALS(A, B) \
    { \
        uint_least32_t a = (uint_least32_t)(A); \
        uint_least32_t b = (uint_least32_t)(B); \
        if (a != b) { \
            (void)printf("FAIL: %s:%d: %" PRIuLEAST32 " != %" PRIuLEAST32 "\n", __FILE__, __LINE__, a, b); \
            return 1; \
        } \
    }

#define TEST_ASSERT_INT_ARRAY_EQUALS(A, B) \
    for (size_t i = 0; i < (sizeof(A) / sizeof((A)[0])); ++i) { \
        int_least32_t a = (A)[i]; \
        int_least32_t b = (B)[i]; \
        if (a != b) { \
            (void)printf("FAIL: %s:%d: %" PRIiLEAST32 " != %" PRIiLEAST32 " at index %zu\n", __FILE__, __LINE__, a, b, i); \
            return 1; \
        } \
    }

#define TEST_ASSERT_UINT_ARRAY_EQUALS(A, B) \
    for (size_t i = 0; i < (sizeof(A) / sizeof((A)[0])); ++i) { \
        uint_least32_t a = (A)[i]; \
        uint_least32_t b = (B)[i]; \
        if (a != b) { \
            (void)printf("FAIL: %s:%d: %" PRIuLEAST32 " != %" PRIuLEAST32 " at index %zu\n", __FILE__, __LINE__, a, b, i); \
            return 1; \
        } \
    }

#define TEST_ASSERT_STR_EQUALS(A, B) \
    if (strcmp((A), (B)) != 0) { \
        (void)printf("FAIL: %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, (A), (B)); \
        return 1; \
    }

#endif
