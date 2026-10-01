#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
[ "$(uname -m)" = x86_64 ] || { echo 'This build targets Intel Macs (x86_64).'; exit 1; }
task_build="${1:-build}"
task_ssl="${OPENSSL_PREFIX:-/usr/local/opt/openssl@3}"
mkdir -p "$task_build/cache"
task_build="$(cd "$task_build" && pwd -P)"
task_cache="${OPENVPNUI_MODULE_CACHE:-$task_build/cache}"
mkdir -p "$task_cache"
task_cache="$(cd "$task_cache" && pwd -P)"
task_flags=(-swift-version 5 -O -target x86_64-apple-macosx26.0 -module-cache-path "$task_cache")
swiftc "${task_flags[@]}" Shared.swift Vault.swift Helper.swift -framework Security -framework SystemConfiguration -o "$task_build/helper"
swiftc "${task_flags[@]}" Shared.swift Files.swift Vault.swift Certificates.swift AppModel.swift App.swift -framework UserNotifications -framework ServiceManagement -framework SwiftUI -framework AppKit -framework Security -framework Network -o "$task_build/OpenVPNUIMac"
swiftc "${task_flags[@]}" Shared.swift Files.swift Tests.swift -framework Security -o "$task_build/tests"
clang -O2 -arch x86_64 -mmacosx-version-min=26.0 -I"$task_ssl/include" p12tool.c "$task_ssl/lib/libssl.a" "$task_ssl/lib/libcrypto.a" -o "$task_build/p12tool"
swiftc "${task_flags[@]}" Shared.swift Files.swift CLI.swift -framework Security -o "$task_build/openvpnuictl"
swiftc "${task_flags[@]}" -D HELPER_TEST Shared.swift Vault.swift Helper.swift HelperTests.swift -framework Security -framework SystemConfiguration -o "$task_build/helper-tests"
python3 scripts/bundle_legacy.py "$task_ssl" "$task_build/legacy"
"$task_build/tests"
"$task_build/helper-tests"
echo 'App, helper, certificate tool, CLI and offline tests built.'
