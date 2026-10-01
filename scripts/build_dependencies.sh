#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(uname -m)" = x86_64 ] || { echo 'An Intel Mac is required.'; exit 1; }
task_root="$(pwd -P)"
task_prefix="$task_root/.deps/prefix"
task_sources="$task_root/.deps/sources"
mkdir -p "$task_prefix" "$task_sources"
python3 scripts/check_upstream.py
for task_archive in openssl-3.6.2 lzo-2.10 lz4-1.10.0; do
  tar -xzf "$task_root/upstream/$task_archive.tar.gz" -C "$task_sources"
done
export MACOSX_DEPLOYMENT_TARGET=26.0
cd "$task_sources/openssl-3.6.2"
./Configure darwin64-x86_64-cc shared no-tests "--prefix=$task_prefix" --libdir=lib
make -j "${BUILD_JOBS:-4}"
make install_sw
cd "$task_sources/lzo-2.10"
./configure "--prefix=$task_prefix" --disable-shared --enable-static
make -j "${BUILD_JOBS:-4}"
make install
cd "$task_sources/lz4-1.10.0"
make -j "${BUILD_JOBS:-4}" -C lib
make -C lib install "PREFIX=$task_prefix"
echo 'Dependencies built locally. Set OPENSSL_PREFIX, LZO_PREFIX and LZ4_PREFIX to .deps/prefix (absolute path).'
