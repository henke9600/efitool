#include "argparse.h"

#include "test.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct test_state {
    int h_count;
    int v_count;
    const char *o_arg;
    const char *invalid_long_opt;
    char invalid_opt;
    int parse_pos;
};

static void test_state_init(struct test_state *state) {
    state->h_count = 0;
    state->v_count = 0;
    state->o_arg = NULL;
    state->invalid_long_opt = NULL;
    state->invalid_opt = '\0';
    state->parse_pos = -1;
}

static void test_state_parse(struct test_state *state, const char *const *argv) {
    ARGPARSE_BEGIN(argv)
        if (strcmp(argparse_long_opt, "help") == 0)    { argparse_arg = "h"; break; }
        if (strcmp(argparse_long_opt, "output") == 0)  { argparse_arg = "o"; break; }
        if (strcmp(argparse_long_opt, "verbose") == 0) { argparse_arg = "v"; break; }
    ARGPARSE_LONG_OPTS_TO_FLAGS_DELIMITER
        case 'h': {
            ++state->h_count;
            break;
        }
        case 'v': {
            ++state->v_count;
            break;
        }
    ARGPARSE_FLAGS_TO_ARGS_DELIMITER
        case 'o': {
            if (strcmp(argparse_arg, "-") == 0) goto argparse_done;
            state->o_arg = argparse_arg;
            break;
        }
    ARGPARSE_END

    if (argparse_opt != '\0') {
        if (argparse_long_opt != NULL) state->invalid_long_opt = argparse_long_opt;
        else state->invalid_opt = argparse_opt;
    }
    state->parse_pos = argparse_pos;
}

static const char *const test_empty_argv[] = { "prog", NULL };

static int test_empty(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_empty_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 0)
    TEST_ASSERT_INT_EQUALS(state.v_count, 0)
    TEST_ASSERT(state.o_arg == NULL)
    TEST_ASSERT(state.invalid_long_opt == NULL)
    TEST_ASSERT(state.invalid_opt == '\0')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 1)

    return 0;
}

static const char *const test_single_argv[] = { "prog", "-v", NULL };

static int test_single(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_single_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 0)
    TEST_ASSERT_INT_EQUALS(state.v_count, 1)
    TEST_ASSERT(state.o_arg == NULL)
    TEST_ASSERT(state.invalid_long_opt == NULL)
    TEST_ASSERT(state.invalid_opt == '\0')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 2)

    return 0;
}

static const char *const test_single_long_argv[] = { "prog", "--verbose", NULL };

static int test_single_long(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_single_long_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 0)
    TEST_ASSERT_INT_EQUALS(state.v_count, 1)
    TEST_ASSERT(state.o_arg == NULL)
    TEST_ASSERT(state.invalid_long_opt == NULL)
    TEST_ASSERT(state.invalid_opt == '\0')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 2)

    return 0;
}

static const char *const test_single_arg_argv[] = { "prog", "-o", "foo", NULL };

static int test_single_arg(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_single_arg_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 0)
    TEST_ASSERT_INT_EQUALS(state.v_count, 0)
    TEST_ASSERT_STR_EQUALS(state.o_arg, "foo")
    TEST_ASSERT(state.invalid_long_opt == NULL)
    TEST_ASSERT(state.invalid_opt == '\0')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 3)

    return 0;
}

static const char *const test_single_long_arg_argv[] = { "prog", "--output", "foo", NULL };

static int test_single_long_arg(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_single_long_arg_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 0)
    TEST_ASSERT_INT_EQUALS(state.v_count, 0)
    TEST_ASSERT_STR_EQUALS(state.o_arg, "foo")
    TEST_ASSERT(state.invalid_long_opt == NULL)
    TEST_ASSERT(state.invalid_opt == '\0')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 3)

    return 0;
}

static const char *const test_repeated_arg_argv[] = { "prog", "-o", "foo", "-o", "bar", "--output", "baz", NULL };

static int test_repeated_arg(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_repeated_arg_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 0)
    TEST_ASSERT_INT_EQUALS(state.v_count, 0)
    TEST_ASSERT_STR_EQUALS(state.o_arg, "baz")
    TEST_ASSERT(state.invalid_long_opt == NULL)
    TEST_ASSERT(state.invalid_opt == '\0')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 7)

    return 0;
}

static const char *const test_many_argv[] = { "prog", "-v", "-v", "-o", "foo", "-h", NULL };

static int test_many(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_many_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 1)
    TEST_ASSERT_INT_EQUALS(state.v_count, 2)
    TEST_ASSERT_STR_EQUALS(state.o_arg, "foo")
    TEST_ASSERT(state.invalid_long_opt == NULL)
    TEST_ASSERT(state.invalid_opt == '\0')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 6)

    return 0;
}

static const char *const test_many_long_argv[] = { "prog", "--verbose", "--verbose", "--output", "foo", "--help", NULL };

static int test_many_long(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_many_long_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 1)
    TEST_ASSERT_INT_EQUALS(state.v_count, 2)
    TEST_ASSERT_STR_EQUALS(state.o_arg, "foo")
    TEST_ASSERT(state.invalid_long_opt == NULL)
    TEST_ASSERT(state.invalid_opt == '\0')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 6)

    return 0;
}

static const char *const test_many_cluster_argv[] = { "prog", "-vvho", "foo", NULL };

static int test_many_cluster(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_many_cluster_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 1)
    TEST_ASSERT_INT_EQUALS(state.v_count, 2)
    TEST_ASSERT_STR_EQUALS(state.o_arg, "foo")
    TEST_ASSERT(state.invalid_long_opt == NULL)
    TEST_ASSERT(state.invalid_opt == '\0')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 3)

    return 0;
}

static const char *const test_invalid_cluster_argv[] = { "prog", "-vxh", NULL };

static int test_invalid_cluster(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_invalid_cluster_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 0)
    TEST_ASSERT_INT_EQUALS(state.v_count, 1)
    TEST_ASSERT(state.o_arg == NULL)
    TEST_ASSERT(state.invalid_long_opt == NULL)
    TEST_ASSERT(state.invalid_opt == 'x')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 1)

    return 0;
}

static const char *const test_invalid_cluster_arg_argv[] = { "prog", "-voh", "foo", NULL };

static int test_invalid_cluster_arg(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_invalid_cluster_arg_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 0)
    TEST_ASSERT_INT_EQUALS(state.v_count, 1)
    TEST_ASSERT(state.o_arg == NULL)
    TEST_ASSERT(state.invalid_long_opt == NULL)
    TEST_ASSERT(state.invalid_opt == 'o')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 1)

    return 0;
}

static const char *const test_invalid_long_cluster_argv[] = { "prog", "-h-output", "foo", NULL };

static int test_invalid_long_cluster(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_invalid_long_cluster_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 1)
    TEST_ASSERT_INT_EQUALS(state.v_count, 0)
    TEST_ASSERT(state.o_arg == NULL)
    TEST_ASSERT(state.invalid_long_opt == NULL)
    TEST_ASSERT(state.invalid_opt == '-')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 1)

    return 0;
}

static const char *const test_dash_argv[] = { "prog", "-", "-h", NULL };

static int test_dash(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_dash_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 0)
    TEST_ASSERT_INT_EQUALS(state.v_count, 0)
    TEST_ASSERT(state.o_arg == NULL)
    TEST_ASSERT(state.invalid_long_opt == NULL)
    TEST_ASSERT(state.invalid_opt == '\0')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 1)

    return 0;
}

static const char *const test_dashdash_argv[] = { "prog", "--", "-h", NULL };

static int test_dashdash(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_dashdash_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 0)
    TEST_ASSERT_INT_EQUALS(state.v_count, 0)
    TEST_ASSERT(state.o_arg == NULL)
    TEST_ASSERT(state.invalid_long_opt == NULL)
    TEST_ASSERT(state.invalid_opt == '\0')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 2)

    return 0;
}

static const char *const test_invalid_argv[] = { "prog", "-H", NULL };

static int test_invalid(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_invalid_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 0)
    TEST_ASSERT_INT_EQUALS(state.v_count, 0)
    TEST_ASSERT(state.o_arg == NULL)
    TEST_ASSERT(state.invalid_long_opt == NULL)
    TEST_ASSERT(state.invalid_opt == 'H')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 1)

    return 0;
}

static const char *const test_invalid_long_argv[] = { "prog", "--helpp", NULL };

static int test_invalid_long(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_invalid_long_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 0)
    TEST_ASSERT_INT_EQUALS(state.v_count, 0)
    TEST_ASSERT(state.o_arg == NULL)
    TEST_ASSERT_STR_EQUALS(state.invalid_long_opt, "helpp")
    TEST_ASSERT(state.invalid_opt == '\0')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 1)

    return 0;
}

static const char *const test_long_before_invalid_argv[] = { "prog", "--verbose", "-H", NULL };

static int test_long_before_invalid(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_long_before_invalid_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 0)
    TEST_ASSERT_INT_EQUALS(state.v_count, 1)
    TEST_ASSERT(state.o_arg == NULL)
    TEST_ASSERT(state.invalid_long_opt == NULL)
    TEST_ASSERT(state.invalid_opt == 'H')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 2)

    return 0;
}

static const char *const test_missing_arg_argv[] = { "prog", "-o", NULL };

static int test_missing_arg(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_missing_arg_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 0)
    TEST_ASSERT_INT_EQUALS(state.v_count, 0)
    TEST_ASSERT(state.o_arg == NULL)
    TEST_ASSERT(state.invalid_long_opt == NULL)
    TEST_ASSERT(state.invalid_opt == 'o')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 1)

    return 0;
}

static const char *const test_missing_long_arg_argv[] = { "prog", "--output", NULL };

static int test_missing_long_arg(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_missing_long_arg_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 0)
    TEST_ASSERT_INT_EQUALS(state.v_count, 0)
    TEST_ASSERT(state.o_arg == NULL)
    TEST_ASSERT_STR_EQUALS(state.invalid_long_opt, "output")
    TEST_ASSERT(state.invalid_opt == '\0')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 1)

    return 0;
}

static const char *const test_invalid_arg_argv[] = { "prog", "-o", "-", NULL };

static int test_invalid_arg(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_invalid_arg_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 0)
    TEST_ASSERT_INT_EQUALS(state.v_count, 0)
    TEST_ASSERT(state.o_arg == NULL)
    TEST_ASSERT(state.invalid_long_opt == NULL)
    TEST_ASSERT(state.invalid_opt == 'o')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 2)

    return 0;
}

static const char *const test_invalid_long_arg_argv[] = { "prog", "--output", "-", NULL };

static int test_invalid_long_arg(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_invalid_long_arg_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 0)
    TEST_ASSERT_INT_EQUALS(state.v_count, 0)
    TEST_ASSERT(state.o_arg == NULL)
    TEST_ASSERT_STR_EQUALS(state.invalid_long_opt, "output")
    TEST_ASSERT(state.invalid_opt == '\0')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 2)

    return 0;
}

static const char *const test_positional_argv[] = { "prog", "foo", "-h", NULL };

static int test_positional(void) {
    struct test_state state;
    test_state_init(&state);
    test_state_parse(&state, &test_positional_argv[0]);

    TEST_ASSERT_INT_EQUALS(state.h_count, 0)
    TEST_ASSERT_INT_EQUALS(state.v_count, 0)
    TEST_ASSERT(state.o_arg == NULL)
    TEST_ASSERT(state.invalid_long_opt == NULL)
    TEST_ASSERT(state.invalid_opt == '\0')
    TEST_ASSERT_INT_EQUALS(state.parse_pos, 1)

    return 0;
}

int main(void) {
    int failures = 0;
    failures += test_empty();
    failures += test_single();
    failures += test_single_long();
    failures += test_single_arg();
    failures += test_single_long_arg();
    failures += test_repeated_arg();
    failures += test_many();
    failures += test_many_long();
    failures += test_many_cluster();
    failures += test_invalid_cluster();
    failures += test_invalid_cluster_arg();
    failures += test_invalid_long_cluster();
    failures += test_dash();
    failures += test_dashdash();
    failures += test_invalid();
    failures += test_invalid_long();
    failures += test_long_before_invalid();
    failures += test_missing_arg();
    failures += test_missing_long_arg();
    failures += test_invalid_arg();
    failures += test_invalid_long_arg();
    failures += test_positional();

    if (failures == 0) {
        (void)printf("All tests passed!\n");
        return EXIT_SUCCESS;
    }

    (void)printf("%d test(s) failed!\n", failures);
    return EXIT_FAILURE;
}
