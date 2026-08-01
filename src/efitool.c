#include "argparse.h"
#include "build_signature_data.h"
#include "build_signature_list.h"
#include "build_signature_database.h"
#include "build_auth2_data.h"
#include "build_dmpstore_data.h"
#include "build_dmpstore_list.h"
#include "build_efivarfs_data.h"
#include "build_signed_pe.h"
#include "parse_signature_data.h"
#include "parse_signature_list.h"
#include "parse_signature_database.h"
#include "parse_auth2_data.h"
#include "parse_dmpstore_data.h"
#include "parse_dmpstore_list.h"
#include "parse_efivarfs_data.h"
#include "prepare_auth2_signing.h"
#include "prepare_pe_signing.h"
#include "calculate_pe_hash.h"
#include "convert_to_hex.h"
#include "convert_from_hex.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

static int usage(FILE *file, char **argv) {
    return fprintf(
        file,
        "Usage: %s [OPTION]... COMMAND\n"
        "\n"
        "Commands:\n"
        "  build-signature-data      Build signature data from a X509 certificate or PE hash\n"
        "  build-signature-list      Build a signature list from signature data\n"
        "  build-signature-database  Build a signature database from signature lists\n"
        "  build-auth2-data          Build data for a time-based authenticated variable access\n"
        "  build-dmpstore-data       Build a variable entry for a dmpstore list\n"
        "  build-dmpstore-list       Build a list of variables for loading with dmpstore\n"
        "  build-efivarfs-data       Build data for updating a variable through efivarfs\n"
        "  build-signed-pe           Build a signed PE image\n"
        "\n"
        "  parse-signature-data      Parse signature data into a X509 certificate or PE hash\n"
        "  parse-signature-list      Parse a signature list into signature data\n"
        "  parse-signature-database  Parse a signature database into signature lists\n"
        "  parse-auth2-data          Parse time-based authenticated variable access data\n"
        "  parse-dmpstore-data       Parse a dmpstore variable entry\n"
        "  parse-dmpstore-list       Parse a list of variables from reading with dmpstore\n"
        "  parse-efivarfs-data       Parse data from reading a variable through efivarfs\n"
        "\n"
        "  prepare-auth2-signing     Prepare signing of a time-based authenticated variable access\n"
        "  prepare-pe-signing        Prepare signing of a PE image\n"
        "\n"
        "  calculate-pe-hash         Calculate the Authenticode hash of a PE image\n"
        "\n"
        "  convert-to-hex            Convert bytes to a hex string\n"
        "  convert-from-hex          Convert a hex string to bytes\n"
        "\n"
        "Options:\n"
        "  -h, --help  Show this help text\n",
        argv[0]
    );
}

int main(int argc, char **argv) {
    if (argc < 1) return EXIT_FAILURE;

    bool help = false;
    ARGPARSE_BEGIN(argv)
        if (strcmp(argparse_long_opt, "help") == 0) { argparse_arg = "h"; break; }
    ARGPARSE_LONG_OPTS_TO_FLAGS_DELIMITER
        case 'h': {
            help = true;
            break;
        }
    ARGPARSE_FLAGS_TO_ARGS_DELIMITER
    ARGPARSE_END

    if (argparse_opt != '\0') {
        if (argparse_long_opt != NULL) (void)fprintf(stderr, "ERROR: Invalid long option '%s'\n\n", argparse_long_opt);
        else                           (void)fprintf(stderr, "ERROR: Invalid option '%c'\n\n", argparse_opt);
        goto err_usage;
    }

    if (help) {
        return usage(stdout, argv) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    int cmd_argc = argc - argparse_pos;
    char **cmd_argv = argv + argparse_pos;
    char *cmd = cmd_argv[0];
    if (cmd == NULL) {
        (void)fprintf(stderr, "ERROR: Missing COMMAND\n\n");
        goto err_usage;
    } else if (strcmp(cmd, "build-signature-data") == 0) {
        return build_signature_data_main(argv[0], cmd_argv);
    } else if (strcmp(cmd, "build-signature-list") == 0) {
        return build_signature_list_main(argv[0], cmd_argc, cmd_argv);
    } else if (strcmp(cmd, "build-signature-database") == 0) {
        return build_signature_database_main(argv[0], cmd_argv);
    } else if (strcmp(cmd, "build-auth2-data") == 0) {
        return build_auth2_data_main(argv[0], cmd_argv);
    } else if (strcmp(cmd, "build-dmpstore-data") == 0) {
        return build_dmpstore_data_main(argv[0], cmd_argv);
    } else if (strcmp(cmd, "build-dmpstore-list") == 0) {
        return build_dmpstore_list_main(argv[0], cmd_argv);
    } else if (strcmp(cmd, "build-efivarfs-data") == 0) {
        return build_efivarfs_data_main(argv[0], cmd_argv);
    } else if (strcmp(cmd, "build-signed-pe") == 0) {
        return build_signed_pe_main(argv[0], cmd_argv);
    } else if (strcmp(cmd, "parse-signature-data") == 0) {
        return parse_signature_data_main(argv[0], cmd_argv);
    } else if (strcmp(cmd, "parse-signature-list") == 0) {
        return parse_signature_list_main(argv[0], cmd_argv);
    } else if (strcmp(cmd, "parse-signature-database") == 0) {
        return parse_signature_database_main(argv[0], cmd_argv);
    } else if (strcmp(cmd, "parse-auth2-data") == 0) {
        return parse_auth2_data_main(argv[0], cmd_argv);
    } else if (strcmp(cmd, "parse-dmpstore-data") == 0) {
        return parse_dmpstore_data_main(argv[0], cmd_argv);
    } else if (strcmp(cmd, "parse-dmpstore-list") == 0) {
        return parse_dmpstore_list_main(argv[0], cmd_argv);
    } else if (strcmp(cmd, "parse-efivarfs-data") == 0) {
        return parse_efivarfs_data_main(argv[0], cmd_argv);
    } else if (strcmp(cmd, "prepare-auth2-signing") == 0) {
        return prepare_auth2_signing_main(argv[0], cmd_argv);
    } else if (strcmp(cmd, "prepare-pe-signing") == 0) {
        return prepare_pe_signing_main(argv[0], cmd_argv);
    } else if (strcmp(cmd, "calculate-pe-hash") == 0) {
        return calculate_pe_hash_main(argv[0], cmd_argv);
    } else if (strcmp(cmd, "convert-to-hex") == 0) {
        return convert_to_hex_main(argv[0], cmd_argv);
    } else if (strcmp(cmd, "convert-from-hex") == 0) {
        return convert_from_hex_main(argv[0], cmd_argv);
    } else {
        (void)fprintf(stderr, "ERROR: Invalid command '%s'\n\n", cmd);
        goto err_usage;
    }

    err_usage:
    usage(stderr, argv);
    return EXIT_FAILURE;
}
