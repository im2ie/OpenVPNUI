Native OpenVPNUI client for **Intel Macs with macOS 26 or later**. **English remains the default interface language.** Ukrainian is available under **Settings and service → General → Language → Українська**.

Use **OpenVPNUI-Mac-Intel-0.2.4.pkg** to install the application, privileged helper and bundled OpenVPN engine. Quit the app and finish active VPN sessions before installing: the update restarts the VPN helper. Existing local profiles are preserved. Import your own profiles and client certificates after installation.

Version 0.2.4 fixes received/sent totals and download/upload rates remaining at zero on active connections. The helper now removes the carriage return from OpenVPN's CRLF management messages before parsing numeric counters. The previous unit test omitted the real line ending; regression tests now pass CRLF and LF frames through Unix sockets and check both directions, 64-bit values, independent sessions, idle traffic, counter resets, malformed updates and the helper-to-app response.

Install the complete `.pkg` to update the system service. Replacing only the `.app` will not fix the counters. Build, regression tests and installer validation were performed without connecting to a corporate VPN or restarting existing tunnels.

English remains the default, with Ukrainian available in settings. Saved language preferences and the Russian-to-Ukrainian migration are preserved.

The existing profile import/export, certificate and CSR management, Keychain policies, split DNS, menu bar controls, traffic statistics and live logs are included.

Assets:
- `.pkg`: complete installer (recommended).
- `.app.zip`: application bundle; the privileged helper is installed by the `.pkg`.
- `Sources.zip`: application, helper, tools, offline tests, packaging scripts, licenses and complete upstream dependency source archives.
- `SHA256SUMS.txt`: release checksums.

Components are locally ad-hoc signed. The installer has no Developer ID Installer signature or Apple notarization. Offline build, package, cryptography and privacy checks passed; compatibility with every VPN deployment and all macOS interaction scenarios is not claimed. See the repository README and VALIDATION.json for details.

No private organization profiles, certificates, keys, DNS policies or internal addresses are included. Unmodified upstream archives retain their public test fixtures and license notices.
