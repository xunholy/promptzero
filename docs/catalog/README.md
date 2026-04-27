---
name: PromptZero Flipper Zero Ecosystem Catalog
description: World's largest structured index of Flipper Zero firmware, apps, payloads, tools, community, research, education, integrations, hardware mods, and adversarial tracking
type: index
created: 2026-04-25
updated: 2026-04-27
---

# PromptZero Flipper Zero Ecosystem Catalog

The most comprehensive structured catalog of the Flipper Zero ecosystem. Cross-referenced against PromptZero Specs, schema-validated, and auto-refreshed nightly via GitHub Actions.

> **Last snapshot:** 2026-04-27 · **Total entries (index.json):** 48 representative (full catalog: ~600+ rows across all .md files)

## Quick navigation

| Section | Files | Est. Entries | Description |
|---|---|---|---|
| [firmware.md](./firmware.md) | 1 | 11+ | Custom firmware forks |
| [apps.md](./apps.md) | 1 | 233+ | Flipper Apps (FAPs) |
| [attacks.md](./attacks.md) | 1 | 34+ | Attack PoCs |
| [hardware.md](./hardware.md) | 1 | 38+ | Companion hardware |
| **[payloads/](./payloads/)** | 6 | ~130 | Signal/payload databases |
| **[tools/](./tools/)** | 5 | ~110 | Desktop, mobile, web, scripts |
| **[community/](./community/)** | 5 | ~90 | Forums, channels, blogs, events |
| **[research/](./research/)** | 4 | ~90 | Papers, talks, CVEs, advisories |
| **[educational/](./educational/)** | 4 | ~80 | Guides, courses, CTFs |
| **[integrations/](./integrations/)** | 4 | ~75 | HA, automation, cloud, AI |
| **[hardware-mods/](./hardware-mods/)** | 4 | ~85 | Cases, boards, mods, peripherals |
| **[adversarial/](./adversarial/)** | 2 | ~22 | Flagged/adversarial projects |

## Payloads

| File | Description |
|---|---|
| [payloads/subghz.md](./payloads/subghz.md) | Sub-GHz capture repos & signal databases |
| [payloads/nfc.md](./payloads/nfc.md) | NFC dump databases & MIFARE key corpora |
| [payloads/ir.md](./payloads/ir.md) | IR remote codes & databases |
| [payloads/badusb.md](./payloads/badusb.md) | BadUSB / DuckyScript payload repos |
| [payloads/rfid.md](./payloads/rfid.md) | RFID dump databases |
| [payloads/bluetooth.md](./payloads/bluetooth.md) | BLE advertisement / GATT payload repos |

## Tools

| File | Description |
|---|---|
| [tools/desktop.md](./tools/desktop.md) | qFlipper, uFBT, CLI utilities, language bindings |
| [tools/mobile.md](./tools/mobile.md) | Android / iOS companion apps |
| [tools/web.md](./tools/web.md) | Web-based tools & online decoders |
| [tools/scripts.md](./tools/scripts.md) | Automation scripts & helper tools |
| [tools/parsers.md](./tools/parsers.md) | File format parsers & protocol decoders |

## Community

| File | Description |
|---|---|
| [community/forums.md](./community/forums.md) | Discord servers, subreddits, Telegram groups |
| [community/channels.md](./community/channels.md) | YouTube channels, podcasts, streams |
| [community/blogs.md](./community/blogs.md) | Blogs, newsletters, write-ups |
| [community/social.md](./community/social.md) | Twitter/X, Mastodon, Bluesky accounts |
| [community/events.md](./community/events.md) | CTFs, conferences, meetups |

## Research

| File | Description |
|---|---|
| [research/papers.md](./research/papers.md) | Academic papers by protocol family |
| [research/conferences.md](./research/conferences.md) | DEF CON / Black Hat / CCC / USENIX talks |
| [research/cves.md](./research/cves.md) | Relevant CVE index |
| [research/advisories.md](./research/advisories.md) | Vendor security advisories |

## Educational

| File | Description |
|---|---|
| [educational/guides.md](./educational/guides.md) | Tutorials, how-tos, wikis |
| [educational/videos.md](./educational/videos.md) | Educational video series |
| [educational/courses.md](./educational/courses.md) | Paid/free courses & books |
| [educational/ctf.md](./educational/ctf.md) | CTF challenges & badge firmware |

## Integrations

| File | Description |
|---|---|
| [integrations/home_assistant.md](./integrations/home_assistant.md) | Home Assistant add-ons & HACS integrations |
| [integrations/automation.md](./integrations/automation.md) | n8n / Node-RED / MQTT bridges |
| [integrations/cloud.md](./integrations/cloud.md) | Cloud dashboards & remote management |
| [integrations/ai.md](./integrations/ai.md) | AI / LLM tool integrations |

## Hardware Mods

| File | Description |
|---|---|
| [hardware-mods/cases.md](./hardware-mods/cases.md) | 3D-printable cases & enclosures |
| [hardware-mods/boards.md](./hardware-mods/boards.md) | PCBs, daughter boards & capes |
| [hardware-mods/mods.md](./hardware-mods/mods.md) | Hardware modifications |
| [hardware-mods/peripherals.md](./hardware-mods/peripherals.md) | Cables, antennas & accessories |

## Adversarial

| File | Description |
|---|---|
| [adversarial/README.md](./adversarial/README.md) | Ethics & policy statement |
| [adversarial/flagged.md](./adversarial/flagged.md) | Flagged / adversarial projects (URL-withheld policy) |

## Schema & machine-readable exports

| File | Description |
|---|---|
| [schema/entry.schema.json](./schema/entry.schema.json) | JSON Schema draft-07 for every catalog entry |
| [schema/CONTRIBUTING.md](./schema/CONTRIBUTING.md) | How to submit a new entry |
| [index.json](./index.json) | Machine-readable entry dump (matches schema) |
| [index.csv](./index.csv) | CSV mirror for spreadsheet consumers |

Validate all entries: `python scripts/catalog_validate.py docs/catalog/`

Auto-refresh CI: [`.github/workflows/catalog-refresh.yml`](../../.github/workflows/catalog-refresh.yml) — runs nightly, discovers new repos via GitHub topics, link-checks all URLs.

## Existing catalog documents

| Document | Description |
|---|---|
| [firmware.md](./firmware.md) | 11 Flipper custom firmwares with feature diff |
| [apps.md](./apps.md) | 233 community apps from 774 unique FAPs |
| [attacks.md](./attacks.md) | 34 public attack PoCs (2024–2026) |
| [hardware.md](./hardware.md) | 38 companion hardware entries |
| [gap-analysis.md](./gap-analysis.md) | Coverage matrix + Top-30 gaps |
| [phase0-review.md](./phase0-review.md) | Phase 0 hotfix verification |
