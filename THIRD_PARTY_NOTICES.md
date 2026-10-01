# Source provenance and third-party notices

The macOS application, helper, certificate tool and tests were implemented as a
native port of the OpenVPNUI workflows. The reference is the public repository
https://github.com/esptl/OpenVPNUI at commit
091dd0afbed5e4ac6f7a644cf6aab81f76cef0d0. Its original archive, copyright notices,
repository LICENSE and source-level license notices are preserved without changes
in `upstream/openvpnui-original.tar.gz`. References to the upstream author/project
are attribution, not a configured VPN endpoint or a bundled organization profile.

| Component | Version / reference | Source archive | License material |
|---|---|---|---|
| OpenVPNUI reference | 091dd0afbed5e4ac6f7a644cf6aab81f76cef0d0 | openvpnui-original.tar.gz | Original LICENSE and source headers in archive |
| OpenVPN | 2.6.23 | openvpn-2.6.23.tar.gz | licenses/OpenVPN-COPYING, including linking exceptions |
| OpenSSL | 3.6.2 | openssl-3.6.2.tar.gz | licenses/OpenSSL-LICENSE and upstream notices |
| LZO | 2.10 | lzo-2.10.tar.gz | licenses/LZO-COPYING and upstream notices |
| LZ4 | 1.10.0 | lz4-1.10.0.tar.gz | licenses/LZ4-LICENSE and upstream notices |

All archives are included in the complete source distribution and listed in
`upstream/SHA256SUMS.txt`. They include upstream public test data, including sample
certificates and sample keys. Those fixtures are not installed into the application.
Apple SDKs, Swift runtime and system frameworks are provided by macOS / Xcode.
OpenVPN is a trademark of OpenVPN Inc. This independent port is not an official
OpenVPN Inc. product. Refer to each component's preserved license and notices.
