// SPDX-License-Identifier: AGPL-3.0-or-later

package dsmr

// crc16ARC computes CRC-16/ARC (reflected, polynomial 0xA001, initial
// value 0) — the DSMR P1 telegram checksum, taken over the bytes from
// '/' to '!' inclusive.
func crc16ARC(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xA001
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

// obisDescriptions maps the DSMR 5.0 P1 OBIS codes to their meaning
// (DSMR P1 companion standard). Unknown codes are surfaced raw.
var obisDescriptions = map[string]string{
	"1-3:0.2.8":   "P1 version information",
	"0-0:1.0.0":   "timestamp of the telegram (YYMMDDhhmmss + S/W)",
	"0-0:96.1.1":  "electricity meter equipment identifier",
	"1-0:1.8.1":   "energy delivered to client, tariff 1 (kWh)",
	"1-0:1.8.2":   "energy delivered to client, tariff 2 (kWh)",
	"1-0:2.8.1":   "energy delivered by client (return), tariff 1 (kWh)",
	"1-0:2.8.2":   "energy delivered by client (return), tariff 2 (kWh)",
	"0-0:96.14.0": "active tariff indicator",
	"1-0:1.7.0":   "instantaneous power delivered (+P) (kW)",
	"1-0:2.7.0":   "instantaneous power returned (-P) (kW)",
	"0-0:96.7.21": "number of power failures (any phase)",
	"0-0:96.7.9":  "number of long power failures (any phase)",
	"1-0:99.97.0": "power-failure event log",
	"1-0:32.32.0": "number of voltage sags, phase L1",
	"1-0:52.32.0": "number of voltage sags, phase L2",
	"1-0:72.32.0": "number of voltage sags, phase L3",
	"1-0:32.36.0": "number of voltage swells, phase L1",
	"1-0:52.36.0": "number of voltage swells, phase L2",
	"1-0:72.36.0": "number of voltage swells, phase L3",
	"0-0:96.13.1": "text message code",
	"0-0:96.13.0": "text message",
	"1-0:32.7.0":  "instantaneous voltage, phase L1 (V)",
	"1-0:52.7.0":  "instantaneous voltage, phase L2 (V)",
	"1-0:72.7.0":  "instantaneous voltage, phase L3 (V)",
	"1-0:31.7.0":  "instantaneous current, phase L1 (A)",
	"1-0:51.7.0":  "instantaneous current, phase L2 (A)",
	"1-0:71.7.0":  "instantaneous current, phase L3 (A)",
	"1-0:21.7.0":  "instantaneous power delivered, phase L1 (+P) (kW)",
	"1-0:41.7.0":  "instantaneous power delivered, phase L2 (+P) (kW)",
	"1-0:61.7.0":  "instantaneous power delivered, phase L3 (+P) (kW)",
	"1-0:22.7.0":  "instantaneous power returned, phase L1 (-P) (kW)",
	"1-0:42.7.0":  "instantaneous power returned, phase L2 (-P) (kW)",
	"1-0:62.7.0":  "instantaneous power returned, phase L3 (-P) (kW)",
	"0-1:24.1.0":  "M-Bus device type (channel 1, e.g. gas)",
	"0-1:96.1.0":  "M-Bus equipment identifier (channel 1)",
	"0-1:24.2.1":  "M-Bus meter reading (channel 1, e.g. gas volume) (timestamp + m3)",
	"0-2:24.1.0":  "M-Bus device type (channel 2)",
	"0-2:96.1.0":  "M-Bus equipment identifier (channel 2)",
	"0-2:24.2.1":  "M-Bus meter reading (channel 2)",
}

func obisDescription(code string) string {
	if d, ok := obisDescriptions[code]; ok {
		return d
	}
	return ""
}
