#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
task_build="${1:-build}"
mkdir -p "$task_build"
task_build="$(cd "$task_build" && pwd -P)"
task_output="$task_build/localization-preview"
task_stage="$(mktemp -d /private/tmp/openvpnui-preview.XXXXXX)"
trap 'rm -rf "$task_stage"' EXIT
task_bundle="$task_stage/OpenVPNUI Localization Preview.app"
mkdir -p "$task_bundle/Contents/MacOS" "$task_build/cache" "$task_output"
swiftc -swift-version 5 -O -D RENDER_PREVIEW -target x86_64-apple-macosx26.0 \
  -module-cache-path "${OPENVPNUI_MODULE_CACHE:-$task_build/cache}" \
  Localization.swift Translations.swift Shared.swift Files.swift Vault.swift Certificates.swift AppModel.swift App.swift tests/RenderLocalization.swift \
  -framework UserNotifications -framework ServiceManagement -framework SwiftUI -framework AppKit -framework Security -framework Network \
  -o "$task_bundle/Contents/MacOS/RenderLocalization"
python3 - "$task_bundle" <<'PY'
from pathlib import Path
import plistlib,sys
path=Path(sys.argv[1])/'Contents/Info.plist'
path.write_bytes(plistlib.dumps({'CFBundleIdentifier':'com.local.openvpnui.localization-preview','CFBundleName':'OpenVPNUI Localization Preview','CFBundleExecutable':'RenderLocalization','CFBundlePackageType':'APPL','CFBundleDevelopmentRegion':'en','LSUIElement':True}))
PY
xattr -cr "$task_bundle"
codesign --force --sign - --timestamp=none "$task_bundle"
rm -f "$task_output/result.txt"
open -n -W "$task_bundle" --args "$task_output"
cat "$task_output/result.txt"
