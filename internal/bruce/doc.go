// Package bruce interfaces with the Bruce pentesting firmware for ESP32-based
// boards over a USB-serial connection.
//
// Bruce firmware (https://github.com/pr3y/Bruce, 5.4k★) is an open-source
// offensive-security firmware for ESP32, M5Stack Cardputer, M5StickC,
// T-Display-S3, ESP32-C5 (5 GHz), and Cheap Yellow Display boards. It
// supports Wi-Fi (2.4 GHz and 5 GHz on C5), BLE scanning/spam, RF analysis,
// IR replay, NFC via PN532, BadUSB via the USB HID stack, Zigbee/IEEE 802.15.4
// passive scanning, and LoRa — all navigated through a text-mode serial menu.
//
// # Protocol
//
// Bruce uses USB CDC-ACM at 115 200 baud, 8N1. The interface is a text-mode
// interactive menu: pressing Enter (sending "\n") selects the highlighted item
// or advances to the next prompt.  Commands can also be sent as full strings
// followed by "\n".  Bruce echoes each command line back and then produces
// line-buffered output. There is no fixed end-of-response sentinel: callers
// use a configurable idle/line-count heuristic (or a known termination token
// per command family).
//
// # Capability detection
//
// Bruce prints a boot banner over serial that identifies the board model and
// firmware version, for example:
//
//	"Bruce 1.0.4 M5StackCardputer"
//	"Bruce 1.2 ESP32-C5 5G"
//
// The [ParseBanner] function extracts [Capabilities] from that banner.
// HasFiveGHz is set when the banner contains "ESP32-C5" or "5G/5g".
// HasZigbee is true for banner strings that include "Zigbee".
// BoardType is the normalized lowercase board identifier.
//
// # References
//
//   - Firmware source: https://github.com/pr3y/Bruce
//   - Wiki:            https://github.com/pr3y/Bruce/wiki
//   - Supported boards: https://github.com/pr3y/Bruce/wiki/Supported-Boards
package bruce
