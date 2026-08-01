#include "build_efivarfs_data.h"
#include "argparse.h"
#include "efi.h"
#include "file.h"
#include "util.h"
#include "x.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int build_efivarfs_data(
    uint_least32_t attributes,
    char *input_var_data,
    char *output_efivarfs_data
) {
    int status = -1;
    unsigned char *input_buffer = NULL;
    struct file out;
    file_init(&out);

    size_t input_size;
    if (util_read_full(input_var_data, &input_buffer, &input_size) < 0) goto err_cleanup;

    if (file_open(&out, output_efivarfs_data, FILE_MODE_WRITE) < 0) goto err_cleanup;

    {
        unsigned char bytes[4];
        x_store_u32(attributes, &bytes[0]);
        if (file_write(&out, &bytes[0], sizeof(bytes)) < 0) goto err_cleanup;
    }
    if (file_write(&out, input_buffer, input_size) < 0) goto err_cleanup;

    status = 0;

    err_cleanup:
    free(input_buffer);
    if (file_close(&out) < 0) status = -1;
    return status;
}

static int build_efivarfs_data_usage(FILE *file, char *parent, char **argv) {
    return fprintf(
        file,
        "Usage: %s %s [OPTION]... VARIABLE_DATA\n"
        "\n"
        "Options:\n"
        "  -h, --help                    Show this help text\n"
        "  -o, --output FILE             Output file. Defaults to stdout\n"
        "  -n, --non-volatile            Set the non-volatile attribute\n"
        "  -b, --bootservice-access      Set the bootservice access attribute\n"
        "  -r, --runtime-access          Set the runtime access attribute\n"
        "  -a, --append-write            Set the append write attribute\n"
        "  -t, --time-based-auth-access  Set the time based authenticated access attribute\n",
        parent,
        argv[0]
    );
}

int build_efivarfs_data_main(char *parent, char **argv) {
    bool help = false;
    char *output_file = "-";
    uint_least32_t attributes = 0;
    ARGPARSE_BEGIN(argv)
        if (strcmp(argparse_long_opt, "help") == 0)                   { argparse_arg = "h"; break; }
        if (strcmp(argparse_long_opt, "output") == 0)                 { argparse_arg = "o"; break; }
        if (strcmp(argparse_long_opt, "non-volatile") == 0)           { argparse_arg = "n"; break; }
        if (strcmp(argparse_long_opt, "bootservice-access") == 0)     { argparse_arg = "b"; break; }
        if (strcmp(argparse_long_opt, "runtime-access") == 0)         { argparse_arg = "r"; break; }
        if (strcmp(argparse_long_opt, "append-write") == 0)           { argparse_arg = "a"; break; }
        if (strcmp(argparse_long_opt, "time-based-auth-access") == 0) { argparse_arg = "t"; break; }
    ARGPARSE_LONG_OPTS_TO_FLAGS_DELIMITER
        case 'h': {
            help = true;
            break;
        }
        case 'n': {
            attributes |= EFI_VARIABLE_NON_VOLATILE;
            break;
        }
        case 'b': {
            attributes |= EFI_VARIABLE_BOOTSERVICE_ACCESS;
            break;
        }
        case 'r': {
            attributes |= EFI_VARIABLE_RUNTIME_ACCESS;
            break;
        }
        case 'a': {
            attributes |= EFI_VARIABLE_APPEND_WRITE;
            break;
        }
        case 't': {
            attributes |= EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
            break;
        }
    ARGPARSE_FLAGS_TO_ARGS_DELIMITER
        case 'o': {
            output_file = argparse_arg;
            break;
        }
    ARGPARSE_END

    if (argparse_opt != '\0') {
        if (argparse_long_opt != NULL) (void)fprintf(stderr, "ERROR: Invalid long option '%s'\n\n", argparse_long_opt);
        else                           (void)fprintf(stderr, "ERROR: Invalid option '%c'\n\n", argparse_opt);
        goto err_usage;
    }

    if (help) {
        return build_efivarfs_data_usage(stdout, parent, argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    char *variable_data = argv[argparse_pos++];
    if (variable_data == NULL) {
        (void)fprintf(stderr, "ERROR: Missing VARIABLE_DATA\n\n");
        goto err_usage;
    }

    if (argv[argparse_pos] != NULL) {
        (void)fprintf(stderr, "ERROR: Too many arguments\n\n");
        goto err_usage;
    }

    return build_efivarfs_data(attributes, variable_data, output_file) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;

    err_usage:
    build_efivarfs_data_usage(stderr, parent, argv);
    return EXIT_FAILURE;
}
