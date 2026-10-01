# OpenVPNUI Mac 0.2.1

A native SwiftUI OpenVPN client for Intel Macs running macOS 26 or later.
The interface is currently in Russian. This is an independent macOS port of the
workflows in [OpenVPNUI](https://github.com/esptl/OpenVPNUI), reference commit
`091dd0afbed5e4ac6f7a644cf6aab81f76cef0d0`.

## Install

Use `OpenVPNUI-Mac-Intel-0.2.1.pkg`. It installs the application, a launchd helper,
and a bundled OpenVPN engine. Homebrew is not required to run the application.
Installation requires administrator authorization and restarts the helper, which
interrupts any tunnels managed by a previous version. Existing user profiles are
kept. Start `/Applications/OpenVPNUI Mac.app` and import your own configuration
and client identity. The distribution contains no configured VPN connection.

The application and components have local ad-hoc signatures. The installer is
not signed with a Developer ID Installer certificate or notarized by Apple.

## Features

- Multiple profiles and tunnels, menu bar controls, credentials and retry,
  traffic counters, connection phases, and an in-memory redacted log.
- `.openvpn` ZIP/XML and `.ovpn`/`.conf` import/export, profile editing, CA and
  client identity selection, TLS assets and imported settings locks.
- Independent VPN/password-key policies: none, session, Keychain, or ask on login.
- P12/PFX, legacy Windows PFX, PEM keys, public certificates, certificate details,
  export, password changes, RSA 4096 / ECDSA P-384 CSR and CA-response import.
- Login launch and optional per-profile automatic connection and reconnect.
- Split DNS through macOS supplemental resolvers, explicit per-profile rules,
  administrator-controlled local group access, and service restart.
- `openvpnuictl` for status, logs, connect/disconnect and profile creation.

See [FEATURES.md](FEATURES.md) for the reference workflow mapping.

### DNS

The profile option **“Считать подключение успешным только при настроенном Split
DNS”** requires at least one valid split DNS rule before a connection is considered
successful. It defaults to enabled. Supply scoped DNS servers and domains through
server PUSH or explicit profile rules. Search domains alone do not supply a DNS server.
Disable that requirement if your deployment intentionally does not need VPN DNS.
This permits an empty DNS configuration; it does not suppress DNS setup errors.

Global DNS, DoH/DoT, nonstandard DNS ports, required DNSSEC and conflicting resolver
policies are not supported. The optional Windows migration utility imports only
user-supplied material; a DNS snapshot must be assigned to profiles explicitly.

## Source and build

This source distribution includes all native application/helper/tool sources,
offline tests, packaging scripts, icons, licenses and the source archives for
OpenVPN 2.6.23, OpenSSL 3.6.2, LZO 2.10 and LZ4 1.10.0. The unmodified reference
Windows repository is included for provenance. Upstream test/sample certificates
and keys remain inside their original source archives; they are public fixtures.

Build prerequisites: an Intel Mac, Xcode Command Line Tools with macOS 26 SDK /
Swift 6.3, Python 3.11 or later, make and Perl. `cryptography` is additionally needed
for the synthetic certificate tests. Runtime binaries target x86_64 macOS 26.

Use existing Intel Homebrew prefixes for the exact dependency versions above, or
build the supplied archives locally without installing dependencies system-wide:

```sh
bash scripts/build_dependencies.sh
export OPENSSL_PREFIX="$PWD/.deps/prefix"
export LZO_PREFIX="$PWD/.deps/prefix"
export LZ4_PREFIX="$PWD/.deps/prefix"
```

Then build and package:

```sh
bash build.sh
bash scripts/build_engine.sh
python3 tests/validate_crypto.py build/p12tool
python3 package_build.py
python3 scripts/validate_release.py
```

With the exact versions already installed under `/usr/local/opt/openssl@3`,
`/usr/local/opt/lzo`, and `/usr/local/opt/lz4`, the three environment variables are
optional. `BUILD_JOBS` controls dependency/engine make parallelism (default 4).
`build.sh` accepts an output directory. `package_build.py --help` describes the
build, engine and output path overrides. Packaging produces a `.pkg`, application
ZIP and complete source ZIP in `dist/`. No upload or publication occurs. Source packaging uses the explicit
`SOURCE_FILES.txt` allowlist; unrelated local files are not included.

The `.deps` dependency rebuild route is provided for source completeness; the
local verification report identifies which build paths have actually been run.

## Data and security boundaries

User data is stored under `~/Library/Application Support/OpenVPNUI Mac` with
private directory/file permissions. Identities and pending CSR keys are encrypted;
passwords use the selected memory/Keychain policy. The root helper checks the
active console UID/group, validates configuration against an allowlist, and
owns OpenVPN execution and DNS hooks. Profiles cannot execute arbitrary root
scripts, load plugins, or select arbitrary root filesystem paths.

Closing the window keeps the menu bar app active. If the app is quit while leaving
a tunnel running, reopen it for password prompts and app-managed reconnect.
Switching the active console user disconnects that user's tunnels.

## Validation and limitations

Offline tests cover import/export, configuration/XML rejection, settings locks,
DNS parsing/conflicts, authentication challenges, password retention, counters,
short live log delivery, shutdown error preservation, and synthetic cryptography.
The release checker verifies signatures, architecture and bundled dependencies.
These checks do not establish compatibility with every server, MFA flow, DNS
policy, sleep/wake scenario or macOS authorization dialog. See `VALIDATION.json`
for the prepared release's actual checks and remaining limits.

Version 0.2.1 fixes delayed log output and loss of the original shutdown error,
and displays the actual OpenVPN connection phase and reconnect reason.

License texts and provenance are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md),
[LICENSE](LICENSE), `licenses/`, and the unchanged upstream archives.
