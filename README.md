# EFI Tool
The `efitool` application is a CLI for building and parsing various EFI data structures. It's written in portable C99 with no dependencies.

Here are some examples of what it can do:
* Build PK, KEK and db signature databases consisting of X509 certificates or PE hashes
* Sign signature database updates, for replacing or appending while Secure Boot is active
* Format EFI variable data for loading into EFI firmware through efivarfs or dmpstore
* Calculate PE hashes and sign PE images for Secure Boot
* Parse signature databases, and other EFI variables, from efivarfs or dmpstore

## Usage Examples
### Signing EFI Image for Secure Boot
```console
$ efitool calculate-pe-hash -o example.pehash example.efi
$ efitool prepare-pe-signing -o example.tosign example.pehash
$ openssl dgst -sha256 -sign example.key -out example.sig example.tosign
$ efitool build-signed-pe -o signed_example.efi example.cer example.sig example.efi
```

### Reading PK Certificate From Efivarfs
```console
$ global_var_guid=8be4df61-93ca-11d2-aa0d-00e098032b8c
$ efitool parse-efivarfs-data -o PK.sigdb /sys/firmware/efi/efivars/PK-$global_var_guid
$ efitool parse-signature-database -o PK PK.sigdb
$ efitool parse-signature-list -o PK PK1.esl
$ efitool parse-signature-data -o PK.cer PK1.esd
$ openssl x509 -in PK.cer -text -noout
```

### Signed Update of Secure Boot Database
```console
$ timestamp=$(date -u +"%Y-%m-%d %H:%M:%S")
$ owner_guid=$(cat /proc/sys/kernel/random/uuid)
$ sha256_guid=c1c41626-504c-4092-aca9-41f936934328
$ x509_guid=a5c059a1-94e4-4aa7-87b5-ab155c2bf072
$ sec_db_guid=d719b2cb-3d3a-4596-a3bc-dad00e67656f
$ # Build x509 signature list
$ efitool build-signature-data -o example_cert.esd $owner_guid example.cer
$ efitool build-signature-list -o example_cert.esl $x509_guid example_cert.esd
$ # Build sha256 signature list
$ efitool calculate-pe-hash -o example.pehash example.efi
$ efitool calculate-pe-hash -o example2.pehash example2.efi
$ efitool build-signature-data -o example_hash.esd $owner_guid example.pehash
$ efitool build-signature-data -o example_hash2.esd $owner_guid example2.pehash
$ efitool build-signature-list -o example_hashes.esl $sha256_guid example_hash.esd example_hash2.esd
$ # Build signature database
$ efitool build-signature-database -o db.sigdb example_cert.esl example_hashes.esl
$ # Sign db update with KEK
$ efitool prepare-auth2-signing -o db.tosign -nbr --timestamp "$timestamp" db $sec_db_guid db.sigdb
$ openssl dgst -sha256 -sign kek.key -out db.sig db.tosign
$ efitool build-auth2-data -o db.auth --timestamp "$timestamp" kek.cer db.sig db.sigdb
$ # Build variable data in efivarfs format
$ efitool build-efivarfs-data -o db.efivarfs -nbr --time-based-auth-access db.auth
$ # Remove efivarfs write protection, and write the new db to EFI firmware
$ chattr -i /sys/firmware/efi/efivars/db-$sec_db_guid
$ dd if=db.efivarfs obs=$(stat -c %s db.efivarfs) of=/sys/firmware/efi/efivars/db-$sec_db_guid
```

## Building
The only requirement for building `efitool` is a C99 compiler.

### Manual Build
```console
$ cc -o efitool src/*.c
```

### CMake Build
```console
$ cmake -Bbuild -DCMAKE_BUILD_TYPE=Release
$ cmake --build build
```

### EDK2 Build
The EDK2 package `EfiToolPkg` can be used to build `efitool` as an EFI Shell application.

This requires the EDK2 build system and EDK2 libc. An example of setting this up is show below.
```console
$ cd ..
$ git clone https://github.com/tianocore/edk2.git
$ git clone https://github.com/tianocore/edk2-libc.git
$ cd edk2
$ git submodule update --init
$ make -C BaseTools
$ export PACKAGES_PATH=$PWD:$PWD/../edk2-libc:$PWD/../efitool
$ . edksetup.sh
$ build -p EfiToolPkg/EfiTool.dsc -t GCC -a X64 -b RELEASE
$ cp Build/EfiToolPkg/RELEASE_GCC/X64/efitool.efi .
```

### Open Watcom Build
For fun, Open Watcom can be used to build `efitool` for DOS.
```
>wcl -fe=efitool.exe -za99 src\*.c
```

## Development
The following CMake flags are recommended for development using gcc or clang.
```console
$ cmake -Bbuild-dev \
-DCMAKE_C_STANDARD=99 \
-DCMAKE_C_EXTENSIONS=OFF \
-DCMAKE_C_FLAGS="\
-Wall -Wextra -Wpedantic -Wconversion -Wundef -Wshadow -Wmissing-prototypes -Wmissing-variable-declarations \
-fsanitize=undefined,address \
" \
-DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
-DCMAKE_BUILD_TYPE=Debug
$ cmake --build build-dev
```

After building, you can test the program with `test.sh`. It requires clang and openssl to run.
```console
$ EFITOOL=build-dev/efitool ./test.sh
```

There's also `Lint.cmake` which runs various checks on the code. It requires CMake, clang and cppcheck to run.
```console
$ cmake -P Lint.cmake
```
