package jtag

// partNames maps (manufacturer code, part number) to a
// human-readable chip name. Outer key is the JEP106 code; inner
// key is the 16-bit part-number field. Limited to chip families
// that operators commonly target during hardware-recon work.
//
// The part-number space is vendor-defined and not standardised;
// these entries come from the chip data sheets / openocd's
// target-files / urjtag's chip-list. The decoder doesn't depend
// on coverage being complete — unrecognised part numbers fall
// through with PartName="".
var partNames = map[uint16]map[uint16]string{
	// ARM (0x23B) — Cortex-M debug ports, CoreSight components.
	// These often appear as the JTAG IDCODE on ARM SoCs whose
	// vendor wraps a stock ARM debug port.
	0x23B: {
		0xBA00: "ARM Cortex-M JTAG-DP",
		0xBA01: "ARM Cortex-A JTAG-DP",
		0xBA02: "ARM CoreSight JTAG-DP (v2)",
		0xBA03: "ARM Cortex-M0/M0+ JTAG-DP",
		0xBA04: "ARM Cortex-M JTAG-DP (M7)",
		0xBA05: "ARM CoreSight JTAG-DP (DPv2)",
		0xBA11: "ARM Cortex-A57",
	},

	// STMicroelectronics (0x020) — STM32 family
	0x020: {
		0x6415: "STM32L0xx",
		0x6420: "STM32F100xx (low-density value line)",
		0x6422: "STM32F302xx / F303xx",
		0x6431: "STM32F411xx",
		0x6433: "STM32F401xx",
		0x6434: "STM32F410xx",
		0x6438: "STM32F303xx (value line)",
		0x6440: "STM32F051xx",
		0x6444: "STM32F03xxx",
		0x6448: "STM32F070xx / F071xx / F072xx",
		0x645E: "STM32F091xx",
		0x6463: "STM32WB55xx",
		0x6472: "STM32G47x / G48x",
		0x6480: "STM32H7xx",
		0x6481: "STM32F4xxxG (Cortex-M4, 1MB+)",
		0x6482: "STM32F76xx / F77xx",
		0x6483: "STM32G07x / G08x",
		0x6484: "STM32G031 / G041",
		0x6485: "STM32L4xx",
		0x6492: "STM32L4Rx / L4Sx",
	},

	// Microchip / Atmel (0x01F) — AVR + SAM
	0x01F: {
		0x9789: "ATmega328P",
		0x9514: "ATmega32U4",
		0x9602: "ATmega2560",
		0xCD01: "SAM3X8E (Arduino Due)",
		0xCD02: "SAM3A8C",
		0xCD30: "SAMD20",
		0xCD31: "SAMD21",
	},

	// Nordic Semi (0x489)
	0x489: {
		0x1003: "nRF51422",
		0x1005: "nRF51822",
		0x1041: "nRF52832",
		0x1051: "nRF52840",
		0x1071: "nRF52833",
		0x2050: "nRF5340 (Network Core)",
		0x2052: "nRF5340 (Application Core)",
	},

	// Texas Instruments (0x017) — MSP430 + Stellaris/Tiva
	0x017: {
		0x6451: "MSP430F2013",
		0x73C3: "MSP430F5638",
		0x0BB1: "TM4C123GH6PM (Tiva-C)",
		0x0BB2: "TM4C129ENCPDT",
	},

	// Cypress (0x034) — PSoC + FX2/FX3
	0x034: {
		0x4F1F: "PSoC 5LP CY8C58LP",
		0x4E4F: "PSoC 6 CY8C6xxx",
	},

	// Espressif (0x228, 0x5DE)
	0x228: {
		0x4B30: "ESP32 (default IDCODE)",
		0x4FA0: "ESP32-C3",
		0xAF20: "ESP32-S2",
		0x84B0: "ESP32-S3",
	},
	0x5DE: {
		0x4B30: "ESP32",
		0x4FA0: "ESP32-C3",
	},

	// NXP Freescale (0x00E originally; later 0x015 Philips and 0x12B as Vantis)
	0x00E: {
		0x0102: "Kinetis KL27/KL28",
		0x4F1F: "i.MX RT1050",
		0x5BA0: "Kinetis MK20DX256",
	},

	// Bouffalo Lab (0x553) — BL602 / BL702 RISC-V
	0x553: {
		0x6027: "BL602 / BL604",
		0x7026: "BL702",
	},

	// Lattice (0x021) — iCE40 + ECP5
	0x021: {
		0x0100: "iCE40LP1K",
		0x0103: "iCE40HX1K",
		0x0900: "iCE40LP8K",
		0x0A00: "iCE40HX8K",
		0x1100: "ECP5-12",
		0x1110: "ECP5-25",
		0x1112: "ECP5-45",
		0x1113: "ECP5-85",
	},

	// Xilinx (0x049) — Spartan / Artix / Kintex / Virtex
	0x049: {
		0x0414: "Spartan-3 XC3S400",
		0x0E2E: "Spartan-6 XC6SLX9",
		0x036D: "Spartan-6 XC6SLX25",
		0x4A63: "Artix-7 XC7A50T",
		0x4A50: "Artix-7 XC7A35T",
		0x4A4E: "Artix-7 XC7A100T",
	},

	// Altera (0x06E) — Cyclone family
	0x06E: {
		0x020F: "Cyclone IV EP4CE6",
		0x020B: "Cyclone IV EP4CE10",
		0x020E: "Cyclone IV EP4CE22",
		0x0210: "Cyclone IV EP4CE30",
		0x0211: "Cyclone IV EP4CE40",
	},
}
