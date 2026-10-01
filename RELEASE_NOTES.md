Native OpenVPNUI client for **Intel Macs with macOS 26 or later**. **English remains the default interface language.** Ukrainian is available under **Settings and service → General → Language → Українська**.

Use **OpenVPNUI-Mac-Intel-0.2.3.pkg** to install the application, privileged helper and bundled OpenVPN engine. Quit the app and finish active VPN sessions before installing: the update restarts the VPN helper. Existing local profiles are preserved. Import your own profiles and client certificates after installation.

Version 0.2.3 replaces Russian with Ukrainian. A saved Russian choice from 0.2.2 switches to Ukrainian automatically; English remains unchanged. All 334 catalog entries have Ukrainian translations, with persistent English/Ukrainian selection across app screens, profile settings, certificate/CSR tools, credential prompts, connection messages, notifications and menu bar controls. The app language changes without disconnecting tunnels. Some system-provided macOS menus and dialogs update after restarting the app. Upgrades from 0.2.1 start in English. Profile names, server challenges and raw logs are preserved verbatim.

The existing profile import/export, certificate and CSR management, Keychain policies, split DNS, menu bar controls, traffic statistics and live logs are included.

Assets:
- `.pkg`: complete installer (recommended).
- `.app.zip`: application bundle; the privileged helper is installed by the `.pkg`.
- `Sources.zip`: application, helper, tools, offline tests, packaging scripts, licenses and complete upstream dependency source archives.
- `SHA256SUMS.txt`: release checksums.

Components are locally ad-hoc signed. The installer has no Developer ID Installer signature or Apple notarization. Offline build, package, cryptography and privacy checks passed; compatibility with every VPN deployment and all macOS interaction scenarios is not claimed. See the repository README and VALIDATION.json for details.

No private organization profiles, certificates, keys, DNS policies or internal addresses are included. Unmodified upstream archives retain their public test fixtures and license notices.
