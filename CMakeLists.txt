cmake_minimum_required(VERSION 3.15)

project(PQS_Complete C)

# ─── Language standard ────────────────────────────────────────────────
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ─── Output directories (lib / bin) ───────────────────────────────────
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ─── Fetch QSC library (uses the main branch) ─────────────────────────
include(FetchContent)
FetchContent_Declare(
  QSC
  GIT_REPOSITORY https://github.com/QRCS-CORP/QSC.git
  GIT_TAG master
)
FetchContent_MakeAvailable(QSC)

# ─── PQS static library ───────────────────────────────────────────────
file(GLOB_RECURSE PQS_SOURCES
     "Source/PQS/*.c")

add_library(pqs STATIC ${PQS_SOURCES})
target_include_directories(pqs
  PUBLIC
    ${PROJECT_SOURCE_DIR}/Source/PQS/include)
target_link_libraries(pqs PUBLIC qsc)

# ─── PQS client executable ────────────────────────────────────────────
file(GLOB_RECURSE PQS_CLIENT_SOURCES
     "Source/Client/*.c")

add_executable(pqs_client ${PQS_CLIENT_SOURCES})
target_link_libraries(pqs_client PRIVATE pqs)

# ─── PQS server executable ────────────────────────────────────────────
file(GLOB_RECURSE PQS_SERVER_SOURCES
     "Source/Server/*.c")

add_executable(pqs_server ${PQS_SERVER_SOURCES})
target_link_libraries(pqs_server PRIVATE pqs)

# ─── Warnings / strict mode toggle ────────────────────────────────────
option(PQS_STRICT "Treat warnings as errors" ON)

foreach(target pqs pqs_client pqs_server)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 $<$<BOOL:${PQS_STRICT}>:/WX>)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -pedantic
                           $<$<BOOL:${PQS_STRICT}>:-Werror>)
  endif()
endforeach()
