cmake_minimum_required(VERSION 3.18)

project(efitool C)

include(CTest)
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

if(BUILD_TESTING)
    function(add_unit_test name)
        add_executable(test_${name} tests/test_${name}.c)
        target_include_directories(test_${name} PRIVATE src)
        add_test(NAME ${name} COMMAND test_${name})
    endfunction()

    add_unit_test(x)
    add_unit_test(sha256)
endif()

install(
    TARGETS efitool
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
