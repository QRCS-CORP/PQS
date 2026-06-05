#!/usr/bin/env sh
set -eu

BUILD_DIR="${1:-build-sanitizers}"
: "${PQS_QSC_ROOT:=../QSC/QSC}"
: "${PQS_QSMS_ROOT:=../QSMS/QSMS}"

cmake -S . -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DPQS_QSC_ROOT="$PQS_QSC_ROOT" \
  -DPQS_QSMS_ROOT="$PQS_QSMS_ROOT" \
  -DPQS_ENABLE_SANITIZERS=ON \
  -DPQS_WARNINGS_AS_ERRORS=OFF

cmake --build "$BUILD_DIR" --parallel
