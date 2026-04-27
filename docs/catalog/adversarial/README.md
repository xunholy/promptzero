---
type: policy
category: adversarial
created: 2026-04-27
---

# Adversarial Appendix — Ethics & Policy

## Purpose

This appendix catalogs adversarial and potentially harmful projects for **defensive purposes only**. Its goal is to inform defenders, security researchers, and the Flipper Zero community about the threat landscape so they can better identify, detect, and mitigate malicious tooling. Awareness of what attackers use is essential for building effective defenses.

This document is part of [PromptZero](https://github.com/xunholy/promptzero), licensed AGPL-3.0-or-later, designed exclusively for **authorized security research**. PromptZero does not endorse, facilitate, or assist in any unauthorized access, surveillance, fraud, or harm.

## URL-Withholding Policy

URLs for adversarial projects are withheld when one or more of the following conditions apply:

1. **Mass-harm potential** — the tool is designed or marketed specifically to cause harm at scale (e.g., vehicle theft, infrastructure disruption, mass surveillance).
2. **Active exploit distribution** — the project is currently distributing working exploits or malware with no defensive framing.
3. **Legal proceedings** — the project or its operators are subject to active criminal or civil proceedings.
4. **Vendor request** — an affected vendor has formally requested non-amplification.

Legitimate security researchers who need access to withheld references for defensive research purposes may open a GitHub Issue at `https://github.com/xunholy/promptzero/issues` with the `[ADVERSARIAL]` prefix, a description of the research context, and institutional affiliation. Requests are reviewed on a case-by-case basis by the maintainers.

## Harm Categories

| Category | Description |
|----------|-------------|
| A1 | **Scam firmware / fake CFW** — counterfeit or fraudulent custom firmware sold commercially with false capability claims |
| A2 | **Backdoored CFW or FAP** — modified firmware or plugin releases containing hidden malware, reverse shells, or credential stealers |
| A3 | **Underground signal packs** — paid collections of Sub-GHz/NFC/IR captures sold on dark-web/Telegram that contain free community files, or enable fraud |
| A4 | **Malware BadUSB payloads** — DuckyScript/HID payloads designed for unauthorized access, credential theft, or persistence without defensive disclosure |
| A5 | **Brand phishing / Evil Portal kits** — Flipper WiFi DevBoard Evil Portal configurations impersonating legitimate services at scale |
| A6 | **Mass-harm BLE spam** — BLE advertising spam designed to crash, disrupt, or denial-of-service devices (especially emergency services) |
| A7 | **Deauth-as-a-service** — Marauder or WiFi firmware forks marketed explicitly as permanent jammers for residential harassment or stalking |
| A8 | **Stalker tools** — FindMy emulation, BLE tracking, or RSSI triangulation tools designed for covert surveillance without subject awareness |
| A9 | **Cracked / pirated tooling** — unlicensed copies of commercial security tools repackaged as free Flipper accessories |
| A10 | **Cellular / IMSI catchers** — Flipper + companion hardware configured for cellular interception or IMSI harvesting |
| A11 | **EMV / contactless payment emulators** — tools designed for fraudulent contactless payment transactions |
| A12 | **Operator-grade RKE vehicle key recovery** — tools specifically framed for high-value vehicle theft, not generic research |

## Legal Disclaimer

Use of the tools, techniques, or information referenced in this appendix without explicit written authorization from the system or device owner may violate one or more of the following:

- **United States**: Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030); Electronic Communications Privacy Act (ECPA, 18 U.S.C. §§ 2510–2523)
- **United Kingdom**: Computer Misuse Act 1990 (as amended); Investigatory Powers Act 2016
- **Canada**: Criminal Code of Canada §§ 342.1, 430(1.1); Radiocommunication Act R.S.C. 1985 c. R-2
- **European Union**: Directive 2013/40/EU on attacks against information systems; GDPR (Regulation (EU) 2016/679)
- **Australia**: Criminal Code Act 1995 Part 10.7 (Computer offences)
- **International**: Convention on Cybercrime (Budapest Convention), ETS No. 185

**The PromptZero maintainers are not responsible for illegal, unauthorized, or harmful use of any tool, technique, or reference in this catalog.** All research using this project must comply with applicable laws and be performed only on systems you own or have explicit written permission to test.

## Reporting Process

To report a new adversarial project for inclusion in this appendix, or to escalate an existing flagged project:

1. Open a GitHub Issue at `https://github.com/xunholy/promptzero/issues`
2. Use the title prefix `[ADVERSARIAL]`
3. Provide: project name, observed harm category (A1–A12), evidence or source links (will be reviewed privately), and whether you are requesting URL withholding
4. Maintainers aim to review and respond within **14 calendar days**
5. Reports involving active malware or imminent harm will be escalated to CISA/CERT within 48 hours

All reports are treated confidentially. Reporter identity will not be disclosed without consent.

## Cross-References

- [Flagged Projects](flagged.md) — full adversarial project listing with withheld and disclosed URLs
- [awesome-flipper-zero-projects](https://github.com/djsime1/awesome-flipperzero) — community-maintained list of legitimate Flipper projects
