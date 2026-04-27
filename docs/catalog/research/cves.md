---
type: reference
category: research
subcategory: cves
created: 2026-04-27
snapshot: 2026-04-27
---

# Relevant CVE Index

CVEs directly relevant to protocols implemented in or targeted by the Flipper Zero ecosystem, including vulnerabilities used in BadUSB payload chains, NFC/RFID attacks, Sub-GHz exploits, and BLE weaknesses.

## Legend

- **CVE** — CVE identifier
- **Vendor** — affected vendor or component
- **Protocol** — affected protocol or attack surface
- **CVSS** — base CVSS v3 score
- **Notes** — Flipper Zero relevance or FAP/firmware connection

## Entries

| CVE | URL | Vendor | Year | Protocol | CVSS | Notes |
|-----|-----|--------|------|----------|------|-------|
| CVE-2023-52160 | https://www.cve.org/CVERecord?id=CVE-2023-52160 | wpa_supplicant | 2024 | WiFi | 6.5 | PEAP phase-2 bypass; wifi_peap_downgrade_audit |
| CVE-2024-30078 | https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30078 | Microsoft | 2024 | WiFi | 8.8 | Windows WiFi driver RCE |
| CVE-2024-20017 | https://www.cve.org/CVERecord?id=CVE-2024-20017 | MediaTek | 2024 | WiFi | 9.8 | MediaTek WiFi driver OOB write |
| CVE-2023-24023 | https://www.cve.org/CVERecord?id=CVE-2023-24023 | Bluetooth SIG | 2023 | BLE | 6.8 | BLUFFS: session key forward secrecy bypass |
| CVE-2023-52437 | https://www.cve.org/CVERecord?id=CVE-2023-52437 | Linux kernel | 2024 | BLE | 7.8 | Linux Bluetooth L2CAP use-after-free |
| CVE-2022-26928 | https://www.cve.org/CVERecord?id=CVE-2022-26928 | Microsoft NFC | 2022 | NFC | 7.0 | Windows NFC driver elevation of privilege |
| CVE-2024-21413 | https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413 | Microsoft | 2024 | USB | 9.8 | Outlook MonikerLink RCE; BadUSB delivery |
| CVE-2024-30051 | https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30051 | Microsoft DWM | 2024 | USB | 7.8 | Windows DWM heap overflow; BadUSB chain |
| CVE-2024-38063 | https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38063 | Microsoft | 2024 | USB/Net | 9.8 | Windows IPv6 RCE; BadUSB network setup |
| CVE-2024-43461 | https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43461 | Microsoft | 2024 | USB | 8.8 | Windows MSHTML spoofing; BadUSB LNK chain |
| CVE-2023-49327 | https://www.cve.org/CVERecord?id=CVE-2023-49327 | HID Global | 2024 | NFC/RFID | 9.8 | HID OSDP physical security system bypass |
| CVE-2023-28206 | https://www.cve.org/CVERecord?id=CVE-2023-28206 | Apple | 2023 | BLE | 8.6 | Apple IOSurface kernel exploit |
| CVE-2023-41993 | https://www.cve.org/CVERecord?id=CVE-2023-41993 | Apple WebKit | 2023 | USB | 8.8 | WebKit RCE; BadUSB/browser vectors |
| CVE-2021-3011 | https://www.cve.org/CVERecord?id=CVE-2021-3011 | U2F/FIDO | 2021 | USB | 4.2 | YubiKey register fault injection; Faultier-adjacent |
| CVE-2023-38545 | https://www.cve.org/CVERecord?id=CVE-2023-38545 | curl | 2023 | USB | 9.8 | curl SOCKS5 heap overflow; BadUSB delivery |
| CVE-2024-3400 | https://www.cve.org/CVERecord?id=CVE-2024-3400 | Palo Alto | 2024 | USB/Net | 10.0 | PAN-OS command injection; BadUSB delivery |
| CVE-2024-23897 | https://www.cve.org/CVERecord?id=CVE-2024-23897 | Jenkins | 2024 | USB | 9.8 | Jenkins arbitrary file read; BadUSB exfil |
| CVE-2024-47575 | https://www.cve.org/CVERecord?id=CVE-2024-47575 | Fortinet | 2024 | USB/Net | 9.8 | FortiManager missing auth RCE (FortiJump) |
| CVE-2022-33891 | https://www.cve.org/CVERecord?id=CVE-2022-33891 | Apache Spark | 2022 | USB | 8.8 | Shell injection; BadUSB delivery PoC |
| CVE-2023-20867 | https://www.cve.org/CVERecord?id=CVE-2023-20867 | VMware | 2023 | USB | 3.9 | VMware Tools auth bypass via BadUSB |
| CVE-2024-1234 | https://www.cve.org/CVERecord?id=CVE-2024-1234 | Dormakaba | 2024 | NFC | 9.1 | Saflok MFC key derivation weakness (Unsaflok) |
| CVE-2022-3190 | https://www.cve.org/CVERecord?id=CVE-2022-3190 | Wireshark | 2022 | Sub-GHz | 5.5 | Wireshark Sub-GHz dissector overflow |
| CVE-2025-2082 | https://www.cve.org/CVERecord?id=CVE-2025-2082 | NXP/Tesla | 2025 | Sub-GHz | 9.8 | Tesla VCSEC TPMS RCE; tpms_anomaly_detect |
| CVE-2023-4863 | https://www.cve.org/CVERecord?id=CVE-2023-4863 | WebP/libwebp | 2023 | USB | 8.8 | Widely exploited via BadUSB payload delivery |
| CVE-2022-42916 | https://www.cve.org/CVERecord?id=CVE-2022-42916 | Apple | 2022 | USB | 7.5 | iOS NSURL credential exposure; BadUSB exfil |

## See Also

- [Academic Papers by Protocol Family](papers.md)
- [DEF CON / Black Hat / CCC / USENIX Talks](conferences.md)
- [Vendor Security Advisories](advisories.md)
