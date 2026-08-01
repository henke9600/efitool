#!/bin/sh
set -e

EFITOOL="${EFITOOL:-efitool}"
OPENSSL="${OPENSSL:-openssl}"
CLANG="${CLANG:-clang}"

echo_eval() {
    printf "%s\n" "$1" && eval "$1"
}

# UEFI 2.11
# 3.3)
global_variable_guid=8be4df61-93ca-11d2-aa0d-00e098032b8c
# 32.4.1)
cert_sha256_guid=c1c41626-504c-4092-aca9-41f936934328
cert_x509_guid=a5c059a1-94e4-4aa7-87b5-ab155c2bf072
# 32.7.1)
image_security_database_guid=d719b2cb-3d3a-4596-a3bc-dad00e67656f

sb_attrs="--non-volatile --bootservice-access --runtime-access"
sb_update_attrs="$sb_attrs --append-write"
auth_timestamp="2001-02-03 01:02:03"
auth_update_timestamp="2001-02-03 01:02:04"

tmp_dir="$(mktemp -d)"
out_dir="$tmp_dir/out" && mkdir "$out_dir"
cert_dir="$out_dir/cert" && mkdir "$cert_dir"
efi_dir="$out_dir/efi" && mkdir "$efi_dir"
dmpstore_dir="$out_dir/dmpstore" && mkdir "$dmpstore_dir"
efivarfs_dir="$out_dir/efivarfs" && mkdir "$efivarfs_dir"
build_dir="$tmp_dir/build" && mkdir "$build_dir"
parse_dir="$tmp_dir/parse" && mkdir "$parse_dir"
stdout="$tmp_dir/stdout"

# Prepare efi images
cat >"$tmp_dir/test.c.in" <<"END"
#include <stdint.h>
#include <stddef.h>

#define EFI_SUCCESS 0

struct efi_guid {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t data4[8];
};

struct efi_input_key {
    uint16_t scan_code;
    uint16_t unicode_char;
};

struct efi_simple_text_input_protocol {
    void *reset;
    size_t (*read_key_stroke)(struct efi_simple_text_input_protocol *this, struct efi_input_key *key);
    void *wait_for_key;
};

struct efi_simple_text_output_protocol {
    void *reset;
    size_t (*output_string)(struct efi_simple_text_output_protocol *this, uint16_t *string);
    void *test_string;
    void *query_mode;
    void *set_mode;
    void *set_attribute;
    void *clear_screen;
    void *set_cursor_position;
    void *enable_cursor;
    void *mode;
};

struct efi_table_header {
    uint64_t signature;
    uint32_t revision;
    uint32_t header_size;
    uint32_t crc32;
    uint32_t reserved;
};

struct efi_runtime_services {
    struct efi_table_header hdr;
    void *get_time;
    void *set_time;
    void *get_wakeup_time;
    void *set_wakeup_time;
    void *set_virtual_address_map;
    void *convert_pointer;
    size_t (*get_variable)(uint16_t *variable_name, struct efi_guid *vendor_guid, uint32_t *attributes, size_t *data_size, void *data);
    void *get_next_variable_name;
    void *set_variable;
    void *get_next_high_monotonic_count;
    void *reset_system;
    void *update_capsule;
    void *query_capsule_capabilities;
    void *query_variable_info;
};

struct efi_system_table {
    struct efi_table_header hdr;
    uint16_t *firmware_vendor;
    uint32_t firmware_revision;
    void *console_in_handle;
    struct efi_simple_text_input_protocol *con_in;
    void *console_out_handle;
    struct efi_simple_text_output_protocol *con_out;
    void *standard_error_handle;
    struct efi_simple_text_output_protocol *std_err;
    struct efi_runtime_services *runtime_services;
    void *boot_services;
    size_t number_of_table_entries;
    void *configuration_table;
};

size_t efi_main(void *image_handle, struct efi_system_table *system_table) {
    (void)image_handle;

    size_t status;
    uint32_t attributes;
    size_t data_size;
    struct efi_guid global_variable = {
        0x8BE4DF61,
        0x93CA,
        0x11D2,
        { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C }
    };

    uint8_t secure_boot;
    data_size = sizeof(secure_boot);
    status = system_table->runtime_services->get_variable(
        L"SecureBoot",
        &global_variable,
        &attributes,
        &data_size,
        &secure_boot
    );
    if (status != EFI_SUCCESS) return status;

    uint8_t setup_mode;
    data_size = sizeof(setup_mode);
    status = system_table->runtime_services->get_variable(
        L"SetupMode",
        &global_variable,
        &attributes,
        &data_size,
        &setup_mode
    );
    if (status != EFI_SUCCESS) return status;

    uint16_t *secure_boot_str = secure_boot ? L"Enabled" : L"Disabled";
    uint16_t *setup_mode_str = setup_mode ? L"Enabled" : L"Disabled";

    status = system_table->con_out->output_string(system_table->con_out, L"@NAME@\r\n\r\nSecure Boot: ");
    if (status != EFI_SUCCESS) return status;
    status = system_table->con_out->output_string(system_table->con_out, secure_boot_str);
    if (status != EFI_SUCCESS) return status;
    status = system_table->con_out->output_string(system_table->con_out, L"\r\nSetup Mode: ");
    if (status != EFI_SUCCESS) return status;
    status = system_table->con_out->output_string(system_table->con_out, setup_mode_str);
    if (status != EFI_SUCCESS) return status;
    status = system_table->con_out->output_string(system_table->con_out, L"\r\n\r\nPress any key to exit...\r\n");
    if (status != EFI_SUCCESS) return status;

    struct efi_input_key key;
    while (system_table->con_in->read_key_stroke(system_table->con_in, &key) != EFI_SUCCESS);
    return EFI_SUCCESS;
}
END

compile_efi() {
    sed "s/@NAME@/${1##*/}/g" "$tmp_dir/test.c.in" >"$tmp_dir/test.c"
    echo_eval "\
$CLANG -target x86_64-unknown-windows -Wall -Wextra -Werror -fuse-ld=lld -nostdlib -Wl,-subsystem:efi_application -Wl,-entry:efi_main \
-o \"$1\" \"$tmp_dir/test.c\"\
"
}

signed_efi="$efi_dir/signed.efi"
compile_efi "$signed_efi"

hashed_efi="$efi_dir/hashed.efi"
compile_efi "$hashed_efi"

hashed2_efi="$efi_dir/hashed2.efi"
compile_efi "$hashed2_efi"

unsigned_efi="$efi_dir/unsigned.efi"
compile_efi "$unsigned_efi"

# Prepare keys and certificates
pk_key="$cert_dir/pk.key"
pk_cert="$cert_dir/pk.cer"
echo_eval "$OPENSSL genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -outform der -out \"$pk_key\""
echo_eval "$OPENSSL req -new -x509 -keyform der -outform der -subj /CN=PK -key \"$pk_key\" -out \"$pk_cert\" -sha256"
pk_cert_size="$(wc -c <"$pk_cert" | tr -d ' ')"

kek_key="$cert_dir/kek.key"
kek_cert="$cert_dir/kek.cer"
echo_eval "$OPENSSL genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -outform der -out \"$kek_key\""
echo_eval "$OPENSSL req -new -x509 -keyform der -outform der -subj /CN=KEK -key \"$kek_key\" -out \"$kek_cert\" -sha256"
kek_cert_size="$(wc -c <"$kek_cert" | tr -d ' ')"

db_key="$cert_dir/db.key"
echo_eval "$OPENSSL genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -outform der -out \"$db_key\""
db1_cert="$cert_dir/db1.cer"
echo_eval "$OPENSSL req -new -x509 -keyform der -outform der -subj /CN=DB1 -key \"$db_key\" -out \"$db1_cert\" -sha256"
db1_cert_size="$(wc -c <"$db1_cert" | tr -d ' ')"

db2_cert="$cert_dir/db2.cer"
echo_eval "$OPENSSL req -new -x509 -keyform der -outform der -subj /CN=DB2 -key \"$db_key\" -out \"$db2_cert\" -sha256"
db2_cert_size="$(wc -c <"$db2_cert" | tr -d ' ')"

cp "$cert_dir"/*.cer "$build_dir"

other_cert="$cert_dir/other.cer"
echo_eval "$OPENSSL req -new -x509 -keyform der -outform der -subj /CN=Other -key \"$db_key\" -out \"$other_cert\" -sha256"

# Hash efi images
signed_efi_hash="$tmp_dir/signed.pehash"
echo_eval "$EFITOOL calculate-pe-hash -o \"$signed_efi_hash\" \"$signed_efi\""

hashed_efi_hash="$build_dir/hashed.pehash"
echo_eval "$EFITOOL calculate-pe-hash -o \"$hashed_efi_hash\" \"$hashed_efi\""

hashed2_efi_hash="$build_dir/hashed2.pehash"
echo_eval "$EFITOOL calculate-pe-hash -o \"$hashed2_efi_hash\" \"$hashed2_efi\""

unsigned_efi_hash="$build_dir/unsigned.pehash"
echo_eval "$EFITOOL calculate-pe-hash -o \"$unsigned_efi_hash\" \"$unsigned_efi\""

# Sign efi images
signed_efi_tosign="$tmp_dir/signed.tosign"
echo_eval "$EFITOOL prepare-pe-signing -o \"$signed_efi_tosign\" \"$signed_efi_hash\""
signed_efi_sig="$tmp_dir/signed.sig"
echo_eval "$OPENSSL dgst -sha256 -keyform der -sign \"$db_key\" -out \"$signed_efi_sig\" \"$signed_efi_tosign\""
echo_eval "$EFITOOL build-signed-pe -o \"$signed_efi\" \"$db1_cert\" \"$signed_efi_sig\" \"$signed_efi\""
signed_signed_efi_hash="$tmp_dir/signed_signed.pehash"
echo_eval "$EFITOOL calculate-pe-hash -o \"$signed_signed_efi_hash\" \"$signed_efi\""
echo_eval "cmp \"$signed_signed_efi_hash\" \"$signed_efi_hash\""

hashed2_efi_tosign="$tmp_dir/hashed2.tosign"
echo_eval "$EFITOOL prepare-pe-signing -o \"$hashed2_efi_tosign\" \"$hashed2_efi_hash\""
hashed2_efi_sig="$tmp_dir/signed.sig"
echo_eval "$OPENSSL dgst -sha256 -keyform der -sign \"$db_key\" -out \"$hashed2_efi_sig\" \"$hashed2_efi_tosign\""
echo_eval "$EFITOOL build-signed-pe -o \"$hashed2_efi\" \"$other_cert\" \"$hashed2_efi_sig\" \"$hashed2_efi\""
signed_hashed2_efi_hash="$tmp_dir/signed_hashed2.pehash"
echo_eval "$EFITOOL calculate-pe-hash -o \"$signed_hashed2_efi_hash\" \"$hashed2_efi\""
echo_eval "cmp \"$signed_hashed2_efi_hash\" \"$hashed2_efi_hash\""

# Build signature data
pk_cert_owner=4b0e7722-c235-4696-928e-d86fe40dd241
pk_cert_esd="$build_dir/PK11.esd"
echo_eval "$EFITOOL build-signature-data -o \"$pk_cert_esd\" $pk_cert_owner \"$pk_cert\""

kek_cert_owner=2d7f2ca9-bebd-4d3a-9162-b182383dc3de
kek_cert_esd="$build_dir/KEK11.esd"
echo_eval "$EFITOOL build-signature-data -o \"$kek_cert_esd\" $kek_cert_owner \"$kek_cert\""

hashed_efi_owner=08610c35-0edc-4847-b3d1-1838a811407f
hashed_efi_esd="$build_dir/db11.esd"
echo_eval "$EFITOOL build-signature-data -o \"$hashed_efi_esd\" $hashed_efi_owner \"$hashed_efi_hash\""

hashed2_efi_owner=2b52012c-9226-4398-a0c0-e507f3416af5
hashed2_efi_esd="$build_dir/db12.esd"
echo_eval "$EFITOOL build-signature-data -o \"$hashed2_efi_esd\" $hashed2_efi_owner \"$hashed2_efi_hash\""

db1_cert_owner=29f5bcb5-f3fa-4e6d-b700-02b7f22e0a9b
db1_cert_esd="$build_dir/db21.esd"
echo_eval "$EFITOOL build-signature-data -o \"$db1_cert_esd\" $db1_cert_owner \"$db1_cert\""

db2_cert_owner=94e61999-ca9e-4efa-9857-5c0066248f79
db2_cert_esd="$build_dir/db31.esd"
echo_eval "$EFITOOL build-signature-data -o \"$db2_cert_esd\" $db2_cert_owner \"$db2_cert\""

unsigned_efi_owner=854893eb-8034-4211-b6c0-8b68536a11b9
unsigned_efi_esd="$build_dir/db_update11.esd"
echo_eval "$EFITOOL build-signature-data -o \"$unsigned_efi_esd\" $unsigned_efi_owner \"$unsigned_efi_hash\""

# Build signature lists
pk_cert_esl="$build_dir/PK1.esl"
echo_eval "$EFITOOL build-signature-list -o \"$pk_cert_esl\" $cert_x509_guid \"$pk_cert_esd\""

kek_cert_esl="$build_dir/KEK1.esl"
echo_eval "$EFITOOL build-signature-list -o \"$kek_cert_esl\" $cert_x509_guid \"$kek_cert_esd\""

hash_esl="$build_dir/db1.esl"
echo_eval "$EFITOOL build-signature-list -o \"$hash_esl\" $cert_sha256_guid \"$hashed_efi_esd\" \"$hashed2_efi_esd\""

db1_cert_esl="$build_dir/db2.esl"
echo_eval "$EFITOOL build-signature-list -o \"$db1_cert_esl\" $cert_x509_guid \"$db1_cert_esd\""

db2_cert_esl="$build_dir/db3.esl"
echo_eval "$EFITOOL build-signature-list -o \"$db2_cert_esl\" $cert_x509_guid \"$db2_cert_esd\""

unsigned_esl="$build_dir/db_update1.esl"
echo_eval "$EFITOOL build-signature-list -o \"$unsigned_esl\" $cert_sha256_guid \"$unsigned_efi_esd\""

# Build signature databases
pk="$build_dir/pk.sigdb"
echo_eval "$EFITOOL build-signature-database -o \"$pk\" \"$pk_cert_esl\""
echo_eval "cmp \"$pk\" \"$pk_cert_esl\""

kek="$build_dir/kek.sigdb"
echo_eval "$EFITOOL build-signature-database -o \"$kek\" \"$kek_cert_esl\""
echo_eval "cmp \"$kek\" \"$kek_cert_esl\""

db="$build_dir/db.sigdb"
echo_eval "$EFITOOL build-signature-database -o \"$db\" \"$hash_esl\" \"$db1_cert_esl\" \"$db2_cert_esl\""

db_update="$build_dir/db_update.sigdb"
echo_eval "$EFITOOL build-signature-database -o \"$db_update\" \"$unsigned_esl\""

# Build variable authentication 2 data
pk_auth="$build_dir/PK.auth"
pk_sig="$build_dir/PK.sig"
echo_eval "$EFITOOL prepare-auth2-signing -o \"$tmp_dir/PK.tosign\" $sb_attrs PK $global_variable_guid \"$pk\""
echo_eval "$OPENSSL dgst -sha256 -keyform der -sign \"$pk_key\" -out \"$pk_sig\" \"$tmp_dir/PK.tosign\""
echo_eval "$EFITOOL build-auth2-data -o \"$pk_auth\" \"$pk_cert\" \"$pk_sig\" \"$pk\""

kek_auth="$build_dir/KEK.auth"
kek_sig="$build_dir/KEK.sig"
echo_eval "\
$EFITOOL prepare-auth2-signing -o \"$tmp_dir/KEK.tosign\" $sb_attrs --timestamp \"$auth_timestamp\" \
KEK $global_variable_guid \"$kek\"\
"
echo_eval "$OPENSSL dgst -sha256 -keyform der -sign \"$pk_key\" -out \"$kek_sig\" \"$tmp_dir/KEK.tosign\""
echo_eval "$EFITOOL build-auth2-data -o \"$kek_auth\" --timestamp \"$auth_timestamp\" \"$pk_cert\" \"$kek_sig\" \"$kek\""

db_auth="$build_dir/db.auth"
db_sig="$build_dir/db.sig"
echo_eval "\
$EFITOOL prepare-auth2-signing $sb_attrs -o \"$tmp_dir/db.tosign\" --timestamp \"$auth_timestamp\" \
db $image_security_database_guid \"$db\"\
"
echo_eval "$OPENSSL dgst -sha256 -keyform der -sign \"$kek_key\" -out \"$db_sig\" \"$tmp_dir/db.tosign\""
echo_eval "$EFITOOL build-auth2-data -o \"$db_auth\" --timestamp \"$auth_timestamp\" \"$kek_cert\" \"$db_sig\" \"$db\""

db_update_auth="$build_dir/db_update.auth"
db_update_sig="$build_dir/db_update.sig"
echo_eval "\
$EFITOOL prepare-auth2-signing $sb_update_attrs -o \"$tmp_dir/db_update.tosign\" --timestamp \"$auth_update_timestamp\" \
db $image_security_database_guid \"$db_update\"\
"
echo_eval "$OPENSSL dgst -sha256 -keyform der -sign \"$kek_key\" -out \"$db_update_sig\" \"$tmp_dir/db_update.tosign\""
echo_eval "\
$EFITOOL build-auth2-data -o \"$db_update_auth\" --timestamp \"$auth_update_timestamp\" \"$kek_cert\" \"$db_update_sig\" \"$db_update\"\
"

# Build efivarfs data
pk_auth_efivarfs="$efivarfs_dir/PK.efivarfs"
echo_eval "$EFITOOL build-efivarfs-data -o \"$pk_auth_efivarfs\" $sb_attrs --time-based-auth-access \"$pk_auth\""

kek_auth_efivarfs="$efivarfs_dir/KEK.efivarfs"
echo_eval "$EFITOOL build-efivarfs-data -o \"$kek_auth_efivarfs\" $sb_attrs --time-based-auth-access \"$kek_auth\""

db_auth_efivarfs="$efivarfs_dir/db.efivarfs"
echo_eval "$EFITOOL build-efivarfs-data -o \"$db_auth_efivarfs\" $sb_attrs --time-based-auth-access \"$db_auth\""

db_update_auth_efivarfs="$efivarfs_dir/db_update.efivarfs"
echo_eval "$EFITOOL build-efivarfs-data -o \"$db_update_auth_efivarfs\" $sb_update_attrs --time-based-auth-access \"$db_update_auth\""

# Build dmpstore data
pk_auth_dsd="$build_dir/sb1.dsd"
echo_eval "\
$EFITOOL build-dmpstore-data -o \"$pk_auth_dsd\" $sb_attrs --time-based-auth-access \
PK $global_variable_guid \"$pk_auth\"\
"

kek_auth_dsd="$build_dir/sb2.dsd"
echo_eval "$EFITOOL build-dmpstore-data -o \"$kek_auth_dsd\" $sb_attrs --time-based-auth-access \
KEK $global_variable_guid \"$kek_auth\"\
"

db_auth_dsd="$build_dir/sb3.dsd"
echo_eval "$EFITOOL build-dmpstore-data -o \"$db_auth_dsd\" $sb_attrs --time-based-auth-access \
db $image_security_database_guid \"$db_auth\"\
"

db_update_auth_dsd="$build_dir/sb_update1.dsd"
echo_eval "$EFITOOL build-dmpstore-data -o \"$db_update_auth_dsd\" $sb_update_attrs --time-based-auth-access \
db $image_security_database_guid \"$db_update_auth\"\
"

# Build dmpstore list
sb_dsl="$dmpstore_dir/sb.dsl"
echo_eval "$EFITOOL build-dmpstore-list -o \"$sb_dsl\" \"$pk_auth_dsd\" \"$kek_auth_dsd\" \"$db_auth_dsd\""

sb_update_dsl="$dmpstore_dir/sb_update.dsl"
echo_eval "$EFITOOL build-dmpstore-list -o \"$sb_update_dsl\" \"$db_update_auth_dsd\""

# Parse dmpstore list
echo_eval "$EFITOOL parse-dmpstore-list -o \"$parse_dir/sb\" \"$sb_dsl\" >\"$stdout\""
echo_eval "printf '' | cmp \"$stdout\" -"

echo_eval "$EFITOOL parse-dmpstore-list -o \"$parse_dir/sb_update\" \"$sb_update_dsl\" >\"$stdout\""
echo_eval "printf '' | cmp \"$stdout\" -"

# Parse dmpstore data
parse_pk_auth="$parse_dir/${pk_auth##*/}"
parse_kek_auth="$parse_dir/${kek_auth##*/}"
parse_db_auth="$parse_dir/${db_auth##*/}"
parse_db_update_auth="$parse_dir/${db_update_auth##*/}"
for dsd in "$parse_dir"/*.dsd; do
    prefix="${dsd%%.dsd}"
    name="${prefix##*/}"
    if test "$name" = sb1; then
        expected="PK\t$global_variable_guid\t$sb_attrs --time-based-auth-access\n"
        out="$parse_pk_auth"
    elif test "$name" = sb2; then
        expected="KEK\t$global_variable_guid\t$sb_attrs --time-based-auth-access\n"
        out="$parse_kek_auth"
    elif test "$name" = sb3; then
        expected="db\t$image_security_database_guid\t$sb_attrs --time-based-auth-access\n"
        out="$parse_db_auth"
    elif test "$name" = sb_update1; then
        expected="db\t$image_security_database_guid\t$sb_update_attrs --time-based-auth-access\n"
        out="$parse_db_update_auth"
    else exit 1; fi

    test -f "$out" && exit 1
    echo_eval "$EFITOOL parse-dmpstore-data -o \"$out\" \"$dsd\" >\"$stdout\""
    echo_eval "printf '$expected' | cmp \"$stdout\" -"
done

# Parse efivarfs data
tmp_pk_auth="$tmp_dir/${pk_auth##*/}"
echo_eval "$EFITOOL parse-efivarfs-data -o \"$tmp_pk_auth\" \"$pk_auth_efivarfs\" >\"$stdout\""
echo_eval "printf -- '$sb_attrs --time-based-auth-access\n' | cmp \"$stdout\" -"
echo_eval "cmp \"$tmp_pk_auth\" \"$pk_auth\""

tmp_kek_auth="$parse_dir/${kek_auth##*/}"
echo_eval "$EFITOOL parse-efivarfs-data -o \"$tmp_kek_auth\" \"$kek_auth_efivarfs\" >\"$stdout\""
echo_eval "printf -- '$sb_attrs --time-based-auth-access\n' | cmp \"$stdout\" -"
echo_eval "cmp \"$tmp_kek_auth\" \"$kek_auth\""

tmp_db_auth="$parse_dir/${db_auth##*/}"
echo_eval "$EFITOOL parse-efivarfs-data -o \"$tmp_db_auth\" \"$db_auth_efivarfs\" >\"$stdout\""
echo_eval "printf -- '$sb_attrs --time-based-auth-access\n' | cmp \"$stdout\" -"
echo_eval "cmp \"$tmp_db_auth\" \"$db_auth\""

tmp_db_update_auth="$parse_dir/${db_update_auth##*/}"
echo_eval "$EFITOOL parse-efivarfs-data -o \"$tmp_db_update_auth\" \"$db_update_auth_efivarfs\" >\"$stdout\""
echo_eval "printf -- '$sb_update_attrs --time-based-auth-access\n' | cmp \"$stdout\" -"
echo_eval "cmp \"$tmp_db_update_auth\" \"$db_update_auth\""

# Parse variable authentication 2 data
parse_pk="$parse_dir/${pk##*/}"
parse_pk_sig="$parse_dir/${pk_sig##*/}"
tmp_pk_auth_cert="$tmp_dir/pk_auth.cer"
echo_eval "\
$EFITOOL parse-auth2-data -o \"$parse_pk\" -c \"$tmp_pk_auth_cert\" -s \"$parse_pk_sig\" \
\"$parse_pk_auth\" >\"$stdout\"\
"
echo_eval "printf '1970-01-01 00:00:00\n' | cmp \"$stdout\" -"
echo_eval "cmp \"$tmp_pk_auth_cert\" \"$pk_cert\""

parse_kek="$parse_dir/${kek##*/}"
parse_kek_sig="$parse_dir/${kek_sig##*/}"
tmp_kek_auth_cert="$tmp_dir/kek_auth.cer"
echo_eval "\
$EFITOOL parse-auth2-data -o \"$parse_kek\" -c \"$tmp_kek_auth_cert\" -s \"$parse_kek_sig\" \
\"$parse_kek_auth\" >\"$stdout\"\
"
echo_eval "printf '$auth_timestamp\n' | cmp \"$stdout\" -"
echo_eval "cmp \"$tmp_kek_auth_cert\" \"$pk_cert\""

parse_db="$parse_dir/${db##*/}"
parse_db_sig="$parse_dir/${db_sig##*/}"
tmp_db_auth_cert="$tmp_dir/db_auth.cer"
echo_eval "\
$EFITOOL parse-auth2-data -o \"$parse_db\" -c \"$tmp_db_auth_cert\" -s \"$parse_db_sig\" \
\"$parse_db_auth\" >\"$stdout\"\
"
echo_eval "printf '$auth_timestamp\n' | cmp \"$stdout\" -"
echo_eval "cmp \"$tmp_db_auth_cert\" \"$kek_cert\""

parse_db_update="$parse_dir/${db_update##*/}"
parse_db_update_sig="$parse_dir/${db_update_sig##*/}"
tmp_db_update_auth_cert="$tmp_dir/db_update_auth.cer"
echo_eval "\
$EFITOOL parse-auth2-data -o \"$parse_db_update\" -c \"$tmp_db_update_auth_cert\" -s \"$parse_db_update_sig\" \
\"$parse_db_update_auth\" >\"$stdout\"\
"
echo_eval "printf '$auth_update_timestamp\n' | cmp \"$stdout\" -"
echo_eval "cmp \"$tmp_db_update_auth_cert\" \"$kek_cert\""

# Parse signature databases
echo_eval "$EFITOOL parse-signature-database -o \"$parse_dir/PK\" \"$parse_pk\" >\"$stdout\""
echo_eval "printf '' | cmp \"$stdout\" -"

echo_eval "$EFITOOL parse-signature-database -o \"$parse_dir/KEK\" \"$parse_kek\" >\"$stdout\""
echo_eval "printf '' | cmp \"$stdout\" -"

echo_eval "$EFITOOL parse-signature-database -o \"$parse_dir/db\" \"$parse_db\" >\"$stdout\""
echo_eval "printf '' | cmp \"$stdout\" -"

echo_eval "$EFITOOL parse-signature-database -o \"$parse_dir/db_update\" \"$parse_db_update\" >\"$stdout\""
echo_eval "printf '' | cmp \"$stdout\" -"

# Parse signature lists
for esl in "$parse_dir"/*.esl; do
    prefix="${esl%%.esl}"
    name="${prefix##*/}"
    if test "$name" = PK1; then expected="$cert_x509_guid\t$((pk_cert_size + 16 + 28))\t$((pk_cert_size + 16))\n"
    elif test "$name" = KEK1; then expected="$cert_x509_guid\t$((kek_cert_size + 16 + 28))\t$((kek_cert_size + 16))\n"
    elif test "$name" = db1; then expected="$cert_sha256_guid\t$((48 * 2 + 28))\t48\n"
    elif test "$name" = db2; then expected="$cert_x509_guid\t$((db1_cert_size + 16 + 28))\t$((db1_cert_size + 16))\n"
    elif test "$name" = db3; then expected="$cert_x509_guid\t$((db2_cert_size + 16 + 28))\t$((db2_cert_size + 16))\n"
    elif test "$name" = db_update1; then expected="$cert_sha256_guid\t$((48 + 28))\t48\n"
    else exit 1; fi

    echo_eval "$EFITOOL parse-signature-list -o \"$prefix\" \"$esl\" >\"$stdout\""
    echo_eval "printf '$expected' | cmp \"$stdout\" -"
done

# Parse signature data
for esd in "$parse_dir"/*.esd; do
    prefix="${esd%%.esd}"
    name="${prefix##*/}"
    if test "$name" = PK11; then expected="$pk_cert_owner\n"; out="$parse_dir/${pk_cert##*/}"
    elif test "$name" = KEK11; then expected="$kek_cert_owner\n"; out="$parse_dir/${kek_cert##*/}"
    elif test "$name" = db11; then expected="$hashed_efi_owner\n"; out="$parse_dir/${hashed_efi_hash##*/}"
    elif test "$name" = db12; then expected="$hashed2_efi_owner\n"; out="$parse_dir/${hashed2_efi_hash##*/}"
    elif test "$name" = db21; then expected="$db1_cert_owner\n"; out="$parse_dir/${db1_cert##*/}"
    elif test "$name" = db31; then expected="$db2_cert_owner\n"; out="$parse_dir/${db2_cert##*/}"
    elif test "$name" = db_update11; then expected="$unsigned_efi_owner\n"; out="$parse_dir/${unsigned_efi_hash##*/}"
    else exit 1; fi

    test -f "$out" && exit 1
    echo_eval "$EFITOOL parse-signature-data -o \"$out\" \"$esd\" >\"$stdout\""
    echo_eval "printf '$expected' | cmp \"$stdout\" -"
done

# Verify parsed outputs match originals
echo_eval "diff -r \"$build_dir\" \"$parse_dir\""

# Test hex conversion
tmp_empty="$tmp_dir/empty"
: >"$tmp_empty"
echo_eval "$EFITOOL convert-to-hex \"$tmp_empty\" | $EFITOOL convert-from-hex -o \"${tmp_empty}2\" -"
echo_eval "cmp \"$tmp_empty\" \"${tmp_empty}2\""

tmp_hello="$tmp_dir/hello"
printf "Hello" >"$tmp_hello"
echo_eval "$EFITOOL convert-to-hex \"$tmp_hello\" | $EFITOOL convert-from-hex -o \"${tmp_hello}2\" -"
echo_eval "cmp \"$tmp_hello\" \"${tmp_hello}2\""
echo_eval "$EFITOOL convert-to-hex -nl \"$tmp_hello\" | $EFITOOL convert-from-hex -o \"${tmp_hello}3\" -"
echo_eval "cmp \"$tmp_hello\" \"${tmp_hello}3\""

printf "\nTest output files: %s\n" "$out_dir"

printf "\nTests passed!\n"
