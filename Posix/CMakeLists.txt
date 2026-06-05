cmake_minimum_required(VERSION 3.16)

project(PQS VERSION 1.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(PQS_BUILD_APPS "Build PQS client and server console applications" ON)
option(PQS_BUILD_TESTS "Build PQS test harness" ON)
option(PQS_ENABLE_SANITIZERS "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(PQS_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(PQS_ENABLE_HARDENING_FLAGS "Enable POSIX hardening compile and link flags" ON)

set(PQS_QSC_ROOT "${CMAKE_CURRENT_LIST_DIR}/../QSC/QSC" CACHE PATH "Path to the QSC source/include directory")
set(PQS_QSMS_ROOT "${CMAKE_CURRENT_LIST_DIR}/../QSMS/QSMS" CACHE PATH "Path to the QSMS source/include directory")
set(PQS_QSC_LIBRARY "" CACHE FILEPATH "Optional path to a prebuilt QSC static/shared library")
set(PQS_QSMS_LIBRARY "" CACHE FILEPATH "Optional path to a prebuilt QSMS static/shared library")

if(NOT EXISTS "${PQS_QSC_ROOT}")
    message(FATAL_ERROR "PQS_QSC_ROOT does not exist. Set -DPQS_QSC_ROOT=/path/to/QSC/QSC")
endif()

if(NOT EXISTS "${PQS_QSMS_ROOT}")
    message(FATAL_ERROR "PQS_QSMS_ROOT does not exist. Set -DPQS_QSMS_ROOT=/path/to/QSMS/QSMS")
endif()

set(PQS_LIBRARY_SOURCES
    PQS/pqs.c
    PQS/pqsconfig.c
    PQS/pqshelp.c
    PQS/pqskey.c
    PQS/pqslogger.c
    PQS/pqspolicy.c
    PQS/pqsprocess.c
    PQS/pqssandbox.c
    PQS/pqsshell.c
    PQS/pqsuser.c
    PQS/pqsxfer.c
)

add_library(pqs STATIC ${PQS_LIBRARY_SOURCES})
target_include_directories(pqs PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/PQS
    ${PQS_QSC_ROOT}
    ${PQS_QSMS_ROOT}
)

target_compile_definitions(pqs PRIVATE _POSIX_C_SOURCE=200809L)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(pqs PRIVATE -Wall -Wextra -Wpedantic -fstack-protector-strong)

    if(PQS_WARNINGS_AS_ERRORS)
        target_compile_options(pqs PRIVATE -Werror)
    endif()

    if(PQS_ENABLE_HARDENING_FLAGS)
        target_compile_definitions(pqs PRIVATE _FORTIFY_SOURCE=2)
        target_compile_options(pqs PRIVATE -fPIE)
    endif()

    if(PQS_ENABLE_SANITIZERS)
        target_compile_options(pqs PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(pqs PRIVATE -fsanitize=address,undefined)
    endif()
endif()

if(PQS_QSC_LIBRARY)
    target_link_libraries(pqs PUBLIC ${PQS_QSC_LIBRARY})
endif()

if(PQS_QSMS_LIBRARY)
    target_link_libraries(pqs PUBLIC ${PQS_QSMS_LIBRARY})
endif()

function(pqs_apply_executable_flags target_name)
    target_include_directories(${target_name} PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/PQS
        ${PQS_QSC_ROOT}
        ${PQS_QSMS_ROOT}
    )

    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target_name} PRIVATE -Wall -Wextra -Wpedantic -fstack-protector-strong)

        if(PQS_WARNINGS_AS_ERRORS)
            target_compile_options(${target_name} PRIVATE -Werror)
        endif()

        if(PQS_ENABLE_HARDENING_FLAGS)
            target_compile_definitions(${target_name} PRIVATE _FORTIFY_SOURCE=2)
            target_compile_options(${target_name} PRIVATE -fPIE)
            target_link_options(${target_name} PRIVATE -pie -Wl,-z,relro -Wl,-z,now)
        endif()

        if(PQS_ENABLE_SANITIZERS)
            target_compile_options(${target_name} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
            target_link_options(${target_name} PRIVATE -fsanitize=address,undefined)
        endif()
    endif()
endfunction()

if(PQS_BUILD_APPS)
    add_executable(pqs_server Server/appsrv.c)
    target_link_libraries(pqs_server PRIVATE pqs)
    pqs_apply_executable_flags(pqs_server)

    add_executable(pqs_client Client/appclt.c)
    target_link_libraries(pqs_client PRIVATE pqs)
    pqs_apply_executable_flags(pqs_client)
endif()

if(PQS_BUILD_TESTS)
    add_executable(pqs_tests Tests/pqs_test.c)
    target_link_libraries(pqs_tests PRIVATE pqs)
    pqs_apply_executable_flags(pqs_tests)
endif()
