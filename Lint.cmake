cmake_minimum_required(VERSION 3.18)

find_package(Python3 REQUIRED)
find_program(RUN_CLANG_TIDY_SCRIPT run-clang-tidy REQUIRED)
find_program(CLANG_TIDY_EXECUTABLE clang-tidy REQUIRED)
find_program(CPPCHECK_EXECUTABLE cppcheck REQUIRED)

set(SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}")
set(BUILD_DIR "${SOURCE_DIR}/build-lint-temp")
file(REMOVE_RECURSE "${BUILD_DIR}")

string(CONCAT C_WARNINGS
    "-Wall -Wextra -Wpedantic -Wconversion -Wundef -Wshadow -Wmissing-prototypes -Wmissing-variable-declarations "
    "-Wno-deprecated-declarations"
)
string(CONCAT CLANG_TIDY_CHECKS
    "clang-analyzer-*,-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling,"
    "bugprone-*,-bugprone-easily-swappable-parameters,-bugprone-suspicious-include,"
    "performance-*,"
    "portability-*,"
    "cert-*,"
    "misc-*"
)
set(CPPCHECK_SUPPRESS "")

function(lint BUILD_TYPE)
    execute_process(
        COMMAND ${CMAKE_COMMAND} -S ${SOURCE_DIR} -B ${BUILD_DIR} -G Ninja
                -DCMAKE_BUILD_TYPE=${BUILD_TYPE}
                -DCMAKE_C_COMPILER=clang
                -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
                -DCMAKE_C_STANDARD=99
                -DCMAKE_C_EXTENSIONS=OFF
                "-DCMAKE_C_FLAGS=-Werror ${C_WARNINGS}"
                ${EXTRA_CONFIGURE}
        RESULT_VARIABLE result
    )
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "CMake ${BUILD_TYPE} configure failed")
    endif()

    execute_process(
        COMMAND ${CMAKE_COMMAND} --build ${BUILD_DIR}
                ${EXTRA_BUILD}
        RESULT_VARIABLE result
    )
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "CMake ${BUILD_TYPE} build failed")
    endif()

    execute_process(
        COMMAND ${CMAKE_CTEST_COMMAND} --test-dir ${BUILD_DIR} --output-on-failure
        RESULT_VARIABLE result
    )
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "Unit tests ${BUILD_TYPE} failed")
    endif()

    execute_process(
        COMMAND ${Python3_EXECUTABLE} ${RUN_CLANG_TIDY_SCRIPT} -clang-tidy-binary ${CLANG_TIDY_EXECUTABLE}
                -p ${BUILD_DIR}
                -warnings-as-errors=*
                -checks=${CLANG_TIDY_CHECKS}
                -quiet
        RESULT_VARIABLE result
    )
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "Clang tidy ${BUILD_TYPE} lint failed")
    endif()

    execute_process(
        COMMAND ${CPPCHECK_EXECUTABLE}
                --project=${BUILD_DIR}/compile_commands.json
                --error-exitcode=1
                --check-level=exhaustive
                --inconclusive
                --enable=all --suppress=missingIncludeSystem --suppress=checkersReport
                --quiet
                ${CPPCHECK_SUPPRESS}
        RESULT_VARIABLE result
    )
    if(NOT result EQUAL 0)
        message(FATAL_ERROR "Cppcheck ${BUILD_TYPE} lint failed")
    endif()
endfunction()

function(check_textfile FILE)
    file(READ "${FILE}" REMAINING HEX)
    while(TRUE)
        string(FIND "${REMAINING}" "0d" CR_INDEX)
        if(CR_INDEX EQUAL -1)
            break()
        endif()
        math(EXPR INDEX_MOD "${CR_INDEX} % 2")
        if(INDEX_MOD EQUAL 0)
            message(FATAL_ERROR "Carriage return found in ${FILE}")
        endif()
        math(EXPR SEARCH_INDEX "${CR_INDEX} + 2")
        string(SUBSTRING "${REMAINING}" ${SEARCH_INDEX} -1 REMAINING)
    endwhile()

    file(READ "${FILE}" CONTENT)
    if(CONTENT MATCHES "([^]a-zA-Z0-9 \n!\"#$%&'()*+,./:;<=>?@[\\^_`{|}~-])")
        string(HEX "${CMAKE_MATCH_1}" BAD_BYTE)
        message(FATAL_ERROR "Byte 0x${BAD_BYTE} found in ${FILE}")
    endif()
    if(CONTENT MATCHES "\n\n\n")
        message(FATAL_ERROR "Triple newline found in ${FILE}")
    endif()
    if(CONTENT MATCHES " +\n")
        message(FATAL_ERROR "Trailing space found in ${FILE}")
    endif()
    if(NOT CONTENT MATCHES "\n$")
        message(FATAL_ERROR "No final newline found in ${FILE}")
    endif()
    if(CONTENT MATCHES "\n\n$")
        message(FATAL_ERROR "Double final newline found in ${FILE}")
    endif()

    file(STRINGS "${FILE}" LONG_LINES LENGTH_MINIMUM 141)
    if(LONG_LINES)
        message(FATAL_ERROR "Line longer than 140 characters found in ${FILE}")
    endif()
endfunction()

file(GLOB_RECURSE TEXT_FILES "${SOURCE_DIR}/src/*" "${SOURCE_DIR}/EfiToolPkg/*" "${SOURCE_DIR}/tests/*")
list(APPEND TEXT_FILES
    "${SOURCE_DIR}/LICENSE"
    "${SOURCE_DIR}/CMakeLists.txt"
    "${SOURCE_DIR}/Lint.cmake"
    "${SOURCE_DIR}/.gitignore"
    "${SOURCE_DIR}/test.sh"
    "${SOURCE_DIR}/README.md"
)
foreach(FILE ${TEXT_FILES})
    check_textfile(${FILE})
endforeach()

lint(Debug)
lint(Release)
file(REMOVE_RECURSE "${BUILD_DIR}")

message(STATUS "All linter checks passed!")
