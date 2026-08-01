cmake_minimum_required(VERSION 3.18)

project(efitool C)

include(GNUInstallDirs)

add_executable(efitool
    src/efitool.c
    src/build_signature_data.c
    src/build_signature_list.c
    src/build_signature_database.c
    src/build_auth2_data.c
    src/build_dmpstore_data.c
    src/build_dmpstore_list.c
    src/build_efivarfs_data.c
    src/build_signed_pe.c
    src/parse_signature_data.c
    src/parse_signature_list.c
    src/parse_signature_database.c
    src/parse_auth2_data.c
    src/parse_dmpstore_data.c
    src/parse_dmpstore_list.c
    src/parse_efivarfs_data.c
    src/prepare_auth2_signing.c
    src/prepare_pe_signing.c
    src/calculate_pe_hash.c
    src/convert_to_hex.c
    src/convert_from_hex.c
    src/asn1.c
    src/crc32.c
    src/efi.c
    src/file.c
    src/pe.c
    src/sha256.c
    src/util.c
    src/x.c
)

install(
    TARGETS efitool
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
