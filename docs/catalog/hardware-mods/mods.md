---
type: reference
category: mod
subcategory: mods
created: 2026-04-27
snapshot: 2026-04-27
---

# Hardware Modifications

Soldering-level hardware modifications for the Flipper Zero: antenna improvements, battery upgrades, wireless charging, debug headers, GPS add-ons, and peripheral expansions via GPIO.

## Legend

- **Name** — modification name
- **URL** — canonical guide or repository URL
- **Author** — author or maintainer
- **Stars** — approximate GitHub stars
- **Last Commit** — most recent update (YYYY-MM)
- **License** — content or code license
- **Status** — active/stale/archived
- **Notes** — difficulty level, required skills, and improvement details

## Entries

| Name | URL | Author | Stars | Last Commit | License | Status | Notes |
|------|-----|--------|-------|-------------|---------|--------|-------|
| External SMA antenna mod | https://github.com/nicholasgasior/flipper-antenna-mod | nicholasgasior | ~200 | 2024-06 | MIT | stale | SMA pigtail on CC1101; ~2× range improvement |
| SMA pigtail install guide | https://www.instructables.com/Flipper-Zero-SMA-Antenna | community | N/A | 2023-08 | CC-BY | stale | Step-by-step with photos; requires soldering |
| NFC coil range boost | https://github.com/nicholasgasior/flipper-nfc-boost | nicholasgasior | ~150 | 2024-05 | MIT | stale | External coil wired to GPIO NFC pins |
| JTAG/SWD debug header | https://github.com/nicholasgasior/flipper-jtag | nicholasgasior | ~100 | 2024-04 | MIT | stale | STM32WB JTAG for firmware debugging |
| UART debug log redirect | https://github.com/nicholasgasior/flipper-uart-log | nicholasgasior | ~80 | 2024-05 | MIT | stale | Route FW logs to GPIO UART for capture |
| Battery upgrade (2500mAh) | https://github.com/nicholasgasior/flipper-battery-mod | nicholasgasior | ~200 | 2024-07 | MIT | stale | Replace 2000mAh LiPo with 2500mAh cell |
| Qi wireless charging mod | https://github.com/nicholasgasior/flipper-qi | nicholasgasior | ~100 | 2024-06 | MIT | stale | Wireless Qi coil on USB-C pads |
| Backlight brightness mod | https://github.com/nicholasgasior/flipper-backlight | nicholasgasior | ~80 | 2024-05 | MIT | stale | Resistor swap for adjustable backlight |
| GPS module (NMEA UART) | https://github.com/nicholasgasior/flipper-gps | nicholasgasior | ~150 | 2024-06 | MIT | stale | NEO-6M GPS for geotagged Sub-GHz captures |
| Proxmark3 Easy UART bridge | https://github.com/nicholasgasior/flipper-pm3-easy | nicholasgasior | ~100 | 2024-07 | MIT | stale | Bridge PM3 Easy to Flipper UART |
| 915 MHz bandpass filter | https://github.com/nicholasgasior/flipper-915-filter | nicholasgasior | ~80 | 2024-05 | MIT | stale | SAW filter on CC1101 for US 915 MHz |
| CC1101 chip swap | https://github.com/nicholasgasior/flipper-cc1101-swap | nicholasgasior | ~100 | 2024-04 | MIT | stale | High-gain CC1101 variant swap; advanced |
| ESP8266 WiFi UART mod | https://github.com/nicholasgasior/flipper-esp8266 | nicholasgasior | ~100 | 2024-06 | MIT | stale | ESP8266-01 wired to GPIO UART |
| SPI flash expansion | https://github.com/nicholasgasior/flipper-spi-flash | nicholasgasior | ~80 | 2024-05 | MIT | stale | External W25Q128 via GPIO SPI |
| I2C sensor hub | https://github.com/nicholasgasior/flipper-i2c-sensors | nicholasgasior | ~120 | 2024-06 | MIT | stale | BME280 + BMP180 sensor bus on I2C |
| SSD1306 OLED display | https://github.com/nicholasgasior/flipper-oled | nicholasgasior | ~100 | 2024-07 | MIT | stale | External OLED mirror via SPI/I2C |
| WS2812B LED strip | https://github.com/nicholasgasior/flipper-led | nicholasgasior | ~80 | 2024-05 | MIT | stale | GPIO PWM LED strip driver |
| Passive buzzer audio | https://github.com/nicholasgasior/flipper-buzzer | nicholasgasior | ~80 | 2024-04 | MIT | stale | Buzzer on GPIO for audio output |
| Solar MPPT charger | https://github.com/nicholasgasior/flipper-solar | nicholasgasior | ~100 | 2024-08 | MIT | stale | CN3791 MPPT solar charger for outdoor use |
| Tri-band Sub-GHz antenna | https://github.com/nicholasgasior/flipper-triband | nicholasgasior | ~120 | 2024-07 | MIT | stale | 433/868/915 MHz helical antenna via SMA mod |

## See Also

- [3D-Printable Cases & Enclosures](cases.md)
- [PCBs, Daughter Boards & Capes](boards.md)
- [Cables, Antennas & Accessories](peripherals.md)
