# Reference feature audit

Reference: esptl/OpenVPNUI commit 091dd0afbed5e4ac6f7a644cf6aab81f76cef0d0.
All entries below have implementation handlers in this port. Runtime validation
limitations are listed in README; this table does not certify interoperability with every VPN deployment.

| Reference workflow | macOS implementation | Verification |
|---|---|---|
| Interface language | English default, optional Ukrainian, persistent in-app selection | Catalog coverage, preferences and ru-to-uk migration, helper message and interpolation tests |
| Connect, disconnect, cancel, credentials, errors | AppModel + helper management channel | Offline management tests; server pending |
| Connection IP, interface, DNS, traffic, elapsed state | SessionStatus + ConnectionView | CRLF/LF socket frames, totals/rates, 64-bit counters, resets and per-session isolation tested; live tunnel pending |
| Show/hide, copy/clear connection log | bounded root log + ConnectionView | Redaction/bounds tested |
| Tray states, show window, exit, state notification | MenuBarExtra + notification delegate | Compiled; interactive pending |
| Import native connection package | ZIP config.xml/DataContract parser | Round-trip/XML tests |
| Connections and multiple simultaneous interfaces | Per-profile sessions and dynamic utun | No hard-coded two-profile cap; live pending |
| Select client certificate by CA, details | CertificateManager.matches + editor | Synthetic CA chain tested |
| AuthSave/KeyAuthSave and locks | Per-profile memory/Keychain policy | Helper one-time/session behavior tested; Keychain UI pending |
| Autostart and resume after suspend | Login item + per-profile autostart + sleep observer | Implemented; interactive pending |
| Import PFX/P12 and CER/CRT plus KEY | CertificateManager + p12tool | Modern/legacy PFX/PEM tests |
| View/delete certificates | CertificatesView + encrypted identity storage | Implemented; interactive pending |
| RSA4096/ECDSA_P384 enrollment with subject fields | encrypted PKCS8 + PKCS10 CSR | Both algorithms tested |
| Copy CSR/import enrollment response | RequestsView + key-match completion | Signed response and mismatch tested |
| General interface list | utun list | Native counterpart of Windows TAP list |
| Grant/revoke group access, restart service | root access policy + Authorization Services | Missing-token rejection tested; admin UI pending |
| MakeOpenVPNConfig utility | bundled openvpnuictl makefile | Native format uses tested exporter |

Windows Service, CryptoAPI, named pipes, WPF and TAP installation are replaced with
launchd, encrypted identities/Keychain, Unix sockets, SwiftUI and native utun.
The original ConnectionFile.Editor and some original CLI commands contain incomplete
stubs. The macOS profile editor and CLI commands have working handlers rather than
reproducing those stubs.
