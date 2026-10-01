Native OpenVPNUI client for **Intel Macs with macOS 26 or later**. The interface is currently in Russian.

Use **OpenVPNUI-Mac-Intel-0.2.1.pkg** to install the application, privileged helper and bundled OpenVPN engine. Existing local profiles are preserved; installing an update restarts the VPN helper. Import your own profiles and client certificates after installation.

This release includes profile import/export, certificate and CSR management, Keychain password policies, split DNS, menu bar controls, traffic statistics and logs. Version 0.2.1 fixes delayed log output and preserves the original connection error.

Assets:
- `.pkg`: complete installer (recommended).
- `.app.zip`: application bundle; the privileged helper is installed by the `.pkg`.
- `Sources.zip`: application, helper, tools, offline tests, packaging scripts, licenses and complete upstream dependency source archives.
- `SHA256SUMS.txt`: release checksums.

Components are locally ad-hoc signed. The installer has no Developer ID Installer signature or Apple notarization. Offline build, package, cryptography and privacy checks passed; compatibility with every VPN deployment and all macOS interaction scenarios is not claimed. See the repository README and VALIDATION.json for details.

No private organization profiles, certificates, keys, DNS policies or internal addresses are included. Unmodified upstream archives retain their public test fixtures and license notices.
