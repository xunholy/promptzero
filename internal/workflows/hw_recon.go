package workflows

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// defaultHWReconGPIOs is the GPIO pin list HWReconBlackbox samples when
// the caller doesn't override it. Matches the pins exposed on the Flipper
// GPIO header plus the spare PC0/PC1 pair used for I²C.
var defaultHWReconGPIOs = []string{"PA7", "PA6", "PA4", "PB3", "PB2", "PC3", "PC1", "PC0"}

// HWReconBlackbox probes an unknown PCB attached to the Flipper GPIO
// header and returns an aggregated recon report. Probes: i2c scan,
// onewire search, per-pin gpio reads, bt hci_info (metadata), and
// device_info.
//
// Risk is Low — all steps are read-only scans.
//
// Params:
//   - gpios ([]string, optional): override the pin list to sample.
func HWReconBlackbox(ctx context.Context, deps Deps, params map[string]interface{}) (string, error) {
	const wf = "hw_recon_blackbox_device"

	gpios := paramStringList(params, "gpios")
	if len(gpios) == 0 {
		gpios = defaultHWReconGPIOs
	}

	var phases []PhaseResult
	extra := map[string]interface{}{}

	// --- I²C scan ---
	if ctx.Err() != nil {
		return cancelledResult("hardware recon", phases, extra), nil
	}
	p := runPhase("i2c_scan", "i2c_scan", func() (string, error) {
		return deps.Flipper.I2CScan()
	})
	phases = append(phases, p)
	recordPhase(deps.Audit, wf, p, nil, "low")
	i2cAddrs := parseI2CAddresses(p.Output)
	extra["i2c_addresses"] = i2cAddrs

	// --- OneWire search ---
	if ctx.Err() != nil {
		return cancelledResult("hardware recon", phases, extra), nil
	}
	p = runPhase("onewire_search", "onewire_search", func() (string, error) {
		return deps.Flipper.OneWireSearch(10 * time.Second)
	})
	phases = append(phases, p)
	recordPhase(deps.Audit, wf, p, nil, "low")
	onewireDevices := parseOneWireDevices(p.Output)
	extra["onewire_devices"] = onewireDevices

	// --- GPIO reads ---
	gpioState := map[string]int{}
	for _, pin := range gpios {
		if ctx.Err() != nil {
			return cancelledResult("hardware recon", phases, extra), nil
		}
		pinCopy := pin
		pp := runPhase("gpio_"+pinCopy, "gpio_read", func() (string, error) {
			return deps.Flipper.GPIORead(pinCopy)
		})
		phases = append(phases, pp)
		recordPhase(deps.Audit, wf, pp, map[string]string{"pin": pinCopy}, "low")
		gpioState[pinCopy] = gpioValueFromOutput(pp.Output)
	}
	extra["gpio_state"] = gpioState

	// --- BT HCI info ---
	if ctx.Err() != nil {
		return cancelledResult("hardware recon", phases, extra), nil
	}
	p = runPhase("bt_hci_info", "bt_hci_info", func() (string, error) {
		return deps.Flipper.BTHCIInfo()
	})
	phases = append(phases, p)
	recordPhase(deps.Audit, wf, p, nil, "low")

	// --- system_info ---
	if ctx.Err() != nil {
		return cancelledResult("hardware recon", phases, extra), nil
	}
	p = runPhase("system_info", "system_info", func() (string, error) {
		return deps.Flipper.DeviceInfo()
	})
	phases = append(phases, p)
	recordPhase(deps.Audit, wf, p, nil, "low")

	summary := summariseHWRecon(i2cAddrs, onewireDevices, gpioState)
	next := suggestHWReconNextSteps(i2cAddrs, onewireDevices)

	return encode(Result{
		Summary:   summary,
		Phases:    phases,
		NextSteps: next,
		Extra:     extra,
	}), nil
}

// parseI2CAddresses extracts 7-bit I²C addresses from the typical Flipper
// "i2c scan" output. The Flipper prints discovered addresses as 0x-prefixed
// hex bytes; we grep them out. Both lowercase and uppercase hex are
// accepted. Deduplicated in-order.
var i2cAddrPattern = regexp.MustCompile(`0x[0-9A-Fa-f]{2}`)

func parseI2CAddresses(out string) []string {
	matches := i2cAddrPattern.FindAllString(out, -1)
	seen := make(map[string]bool, len(matches))
	addrs := make([]string, 0, len(matches))
	for _, m := range matches {
		norm := strings.ToLower(m)
		if seen[norm] {
			continue
		}
		seen[norm] = true
		addrs = append(addrs, norm)
	}
	return addrs
}

// parseOneWireDevices extracts 1-Wire ROM codes from the Flipper
// "onewire search" output. Devices are printed as 16-hex-char ROM codes
// (sometimes colon-separated); we accept both forms.
var oneWireROMPattern = regexp.MustCompile(`(?:[0-9A-Fa-f]{2}:){7}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{16}`)

func parseOneWireDevices(out string) []string {
	matches := oneWireROMPattern.FindAllString(out, -1)
	seen := make(map[string]bool, len(matches))
	roms := make([]string, 0, len(matches))
	for _, m := range matches {
		norm := strings.ToUpper(strings.ReplaceAll(m, ":", ""))
		if seen[norm] {
			continue
		}
		seen[norm] = true
		roms = append(roms, norm)
	}
	return roms
}

// gpioValueFromOutput parses a `gpio read` line: the Flipper reports
// "Pin X = 0" or "Pin X = 1" (with some fork-to-fork variation). We
// return 1 when the output mentions "high" or an explicit "= 1",
// otherwise 0 — defaulting to 0 on unparseable output is safer than
// misreporting a pin as high.
func gpioValueFromOutput(out string) int {
	l := strings.ToLower(out)
	if strings.Contains(l, "= 1") || strings.Contains(l, "high") {
		return 1
	}
	return 0
}

func summariseHWRecon(i2c, onewire []string, gpio map[string]int) string {
	i2cPart := fmt.Sprintf("I2C: %d devices", len(i2c))
	if len(i2c) > 0 {
		i2cPart += " at " + strings.Join(i2c, ", ")
	}
	onewirePart := fmt.Sprintf("OneWire: %d devices", len(onewire))
	highCount := 0
	for _, v := range gpio {
		if v == 1 {
			highCount++
		}
	}
	gpioPart := fmt.Sprintf("GPIO: %d/%d high", highCount, len(gpio))
	return i2cPart + " / " + onewirePart + " / " + gpioPart
}

// suggestHWReconNextSteps tailors follow-up advice to the probe findings.
// Known I²C addresses get mapped to their typical chip (best-effort — users
// still need to verify on a schematic).
func suggestHWReconNextSteps(i2c, onewire []string) []string {
	var next []string
	for _, a := range i2c {
		switch strings.ToLower(a) {
		case "0x3c", "0x3d":
			next = append(next, fmt.Sprintf("%s is often an SSD1306/SH1106 OLED — try `loader_open \"SSD1306 demo\"` if installed", a))
		case "0x68":
			next = append(next, fmt.Sprintf("%s is often an RTC (DS1307/DS3231) or MPU-6050 IMU — probe with `flipper_raw_cli \"i2c write\"` to disambiguate", a))
		case "0x76", "0x77":
			next = append(next, fmt.Sprintf("%s is often a BMP280/BME280 environmental sensor — `loader_unitemp` can read it", a))
		case "0x50":
			next = append(next, fmt.Sprintf("%s is often an I²C EEPROM (24Cxx) — dump contents via a custom script", a))
		}
	}
	if len(onewire) > 0 {
		next = append(next, fmt.Sprintf("OneWire bus has %d device(s) — `loader_unitemp` can read temperature/humidity sensors automatically", len(onewire)))
	}
	if len(next) == 0 {
		next = append(next, "No common devices identified — try `loader_uart_terminal` for serial recon or `loader_spectrum_analyzer` for RF characterisation")
	}
	return next
}
