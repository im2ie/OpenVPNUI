#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
task_root="$(pwd -P)"
task_build="${1:-$task_root/build}"
mkdir -p "$task_build"
task_build="$(cd "$task_build" && pwd -P)"
task_ssl="${OPENSSL_PREFIX:-/usr/local/opt/openssl@3}"
task_lzo="${LZO_PREFIX:-/usr/local/opt/lzo}"
task_lz4="${LZ4_PREFIX:-/usr/local/opt/lz4}"
python3 scripts/check_upstream.py
mkdir -p "$task_build/engine-source"
tar -xzf upstream/openvpn-2.6.23.tar.gz -C "$task_build/engine-source"
cd "$task_build/engine-source/openvpn-2.6.23"
./configure --disable-plugins --disable-debug --disable-pkcs11 --disable-dependency-tracking --disable-shared --enable-static \
  "OPENSSL_CFLAGS=-I$task_ssl/include" "OPENSSL_LIBS=$task_ssl/lib/libssl.a $task_ssl/lib/libcrypto.a" \
  "LZO_CFLAGS=-I$task_lzo/include" "LZO_LIBS=$task_lzo/lib/liblzo2.a" \
  "LZ4_CFLAGS=-I$task_lz4/include" "LZ4_LIBS=$task_lz4/lib/liblz4.a" MACOSX_DEPLOYMENT_TARGET=26.0
make -j "${BUILD_JOBS:-4}"
cp src/openvpn/openvpn "$task_build/openvpn"
"$task_build/openvpn" --version
