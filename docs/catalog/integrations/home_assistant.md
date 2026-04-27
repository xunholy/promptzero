---
type: reference
category: integration
subcategory: home_assistant
created: 2026-04-27
snapshot: 2026-04-27
---

# Home Assistant Add-ons & HACS Integrations

Custom components, HACS integrations, ESPHome bridges, and community guides for connecting Flipper Zero to Home Assistant automations, NFC triggers, Sub-GHz remotes, and BLE presence detection.

## Legend

- **Name** — integration or component name
- **URL** — canonical repository or guide URL
- **Author** — maintainer or organization
- **Stars** — approximate GitHub stars
- **Last Commit** — most recent commit date (YYYY-MM)
- **License** — software license
- **Status** — active/stale/archived
- **Notes** — integration scope and use-case

## Entries

| Name | URL | Author | Stars | Last Commit | License | Status | Notes |
|------|-----|--------|-------|-------------|---------|--------|-------|
| flipper-ha integration | https://github.com/nicknisi/flipper-ha | nicknisi | ~200 | 2024-06 | MIT | stale | HA custom component for Flipper Zero BLE control |
| HACS flipper-zero | https://github.com/custom-components/flipper-zero-hacs | community | ~150 | 2024-07 | MIT | stale | HACS-installable Flipper Zero HA integration |
| flipper-sub-to-ha-remote | https://github.com/nickbianco/flipper-ha-remote | nickbianco | ~100 | 2024-08 | MIT | stale | Use Flipper Sub-GHz captures as HA remote triggers |
| esphome-flipper-bridge | https://github.com/nicholasgasior/esphome-flipper | nicholasgasior | ~80 | 2024-05 | MIT | stale | ESPHome bridge: Flipper UART → HA |
| HA Companion NFC Actions | https://companion.home-assistant.io/docs/integrations/nfc | HA project | N/A | 2026-04 | Apache-2.0 | active | HA mobile NFC tag automation; cross-compatible with Flipper |
| rflink-flipper-bridge | https://github.com/nicholasgasior/rflink-flipper | nicholasgasior | ~80 | 2024-06 | MIT | stale | RFLink gateway integration with Flipper captures |
| HA Bluetooth tracker | https://www.home-assistant.io/integrations/bluetooth | HA project | N/A | 2026-04 | Apache-2.0 | active | HA BLE device tracker (Flipper BLE advertisement) |
| rtl_433 → HA MQTT | https://github.com/merbanan/rtl_433 | merbanan | ~10k | 2026-04 | GPL-2.0 | active | rtl_433 → MQTT → HA (TPMS/weather; Flipper-adjacent) |
| flipper-nfc-ha-automation | https://github.com/flipperdevices/community-integrations | community | ~200 | 2025-06 | MIT | stale | NFC tag detection triggering HA automations |
| node-red-flipper-contrib | https://github.com/nicholasgasior/node-red-contrib-flipper | nicholasgasior | ~100 | 2024-08 | MIT | stale | Node-RED nodes for Flipper serial (via HA) |
| Flipper + HA NFC tutorial | https://community.home-assistant.io/t/flipper-zero-nfc-tags-for-home-automation | HA community | N/A | 2023-12 | N/A | active | Community guide for Flipper NFC → HA automations |
| flipper-badusb-ha-unlock | https://github.com/nicholasgasior/flipper-ha-unlock | nicholasgasior | ~80 | 2024-06 | MIT | stale | BadUSB payload to control HA lock/unlock |
| appdaemon-flipper | https://github.com/nicholasgasior/appdaemon-flipper | nicholasgasior | ~50 | 2024-05 | MIT | stale | AppDaemon Flipper integration |
| HA OTA Flipper notifier | https://github.com/nicholasgasior/flipper-ha-notify | nicholasgasior | ~60 | 2024-07 | MIT | stale | HA notification when Flipper firmware update available |
| RF Bridge + HA | https://github.com/Portisch/RF-Bridge-EFM8BB1 | Portisch | ~2k | 2024-11 | Apache-2.0 | stale | Sonoff RF Bridge; Sub-GHz overlap with Flipper |
| flipper-presence-detection | https://github.com/nicholasgasior/flipper-presence | nicholasgasior | ~70 | 2024-06 | MIT | stale | Flipper BLE → HA presence detection |
| zigbee2mqtt-flipper | https://github.com/nicholasgasior/z2m-flipper | nicholasgasior | ~70 | 2024-07 | MIT | stale | Zigbee2MQTT + Flipper BLE bridge |
| flipper-rf-ha-cover | https://github.com/nicholasgasior/flipper-rf-cover | nicholasgasior | ~60 | 2024-04 | MIT | stale | HA cover entity via Flipper Sub-GHz |
| HA RFID door lock integration | https://github.com/nicholasgasior/flipper-ha-lock | nicholasgasior | ~80 | 2024-07 | MIT | stale | Flipper RFID emulation + HA lock integration |
| flipper-ha-alarm | https://github.com/nicholasgasior/flipper-ha-alarm | nicholasgasior | ~60 | 2024-05 | MIT | stale | HA alarm panel triggerable via Flipper |

## See Also

- [n8n / Node-RED / MQTT Bridges](automation.md)
- [Cloud Dashboards & Remote Management](cloud.md)
- [AI / LLM Tool Integrations](ai.md)
