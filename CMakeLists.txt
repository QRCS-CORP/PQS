cmake_minimum_required(VERSION 3.15)

project(PQS_Complete C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Output dirs
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Download and build QSC
include(FetchContent)
FetchContent_Declare(
  QSC
  GIT_REPOSITORY https://github.com/QRCS-CORP/QSC.git
  GIT_TAG master
)
FetchContent_MakeAvailable(QSC)

# PQS Static Library
file(GLOB_RECURSE PQS_SOURCES "Source/PQS/*.c")
file(GLOB_RECURSE PQS_HEADERS "Source/PQS/include/*.h")

add_library(pqs STATIC ${SKDP_SOURCES} ${PQS_HEADERS})
target_include_directories(pqs PUBLIC Source/PQS)
target_link_libraries(pqs PUBLIC qsc)

# PQS Client
file(GLOB_RECURSE PQS_CLIENT_SOURCES "Source/PQS Client/*.c")

add_executable(pqs_client ${PQS_CLIENT_SOURCES})
target_include_directories(pqs_client PRIVATE "Source/PQS Client")
target_link_libraries(pqs_client PRIVATE pqs)

# SKDP Server
file(GLOB_RECURSE PQS_SERVER_SOURCES "Source/PQS Server/*.c")

add_executable(pqs_server ${PQS_SERVER_SOURCES})
target_include_directories(pqs_server PRIVATE Source/PQS Server)
target_link_libraries(pqs_server PRIVATE pqs)

# Warnings
foreach(target pqs pqs_client pqs_server)
  if (MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
endforeach()
