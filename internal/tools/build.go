package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/fileformat"
	"github.com/xunholy/promptzero/internal/risk"
)

// build.go registers the parametric file-builder tools (Batch C — P1-13):
//   - subghz_bruteforce_generate
//   - subghz_freq_sweep
//   - subghz_build
//   - rfid_build
//   - ir_build
//   - nfc_build
//
// All are AgentOnly:true because the chain-of-verification verifier
// (BuildVerify) runs an LLM pass before every write. In MCP mode BuildVerify
// is nil and the verification step is skipped, but that mode currently does
// not need these tools.

//nolint:gochecknoinits
func init() {
	Register(Spec{
		Name: "subghz_bruteforce_generate",
		Description: "Generate a RAW .sub file containing a Princeton-style key sweep, written to the SD card. " +
			"Each key is encoded MSB-first with OOK timing (1=long high+short low, 0=short high+long low) plus " +
			"a 31*TE sync gap between keys. Good for replaying a small sweep against a 24-bit PT2240/SC5262-family " +
			"remote that the operator hasn't captured. Cap: 10000 keys per invocation — sweep in windows for wider searches.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"path":{"type":"string","description":"Destination on SD card, e.g. /ext/subghz/sweep.sub"},` +
			`"frequency":{"type":"integer","description":"Frequency in Hz, e.g. 433920000"},` +
			`"bit_count":{"type":"integer","description":"Protocol bit length (typically 24 for Princeton-family)"},` +
			`"start_key":{"type":"integer","description":"Inclusive start of the key range"},` +
			`"end_key":{"type":"integer","description":"Inclusive end of the key range"},` +
			`"te":{"type":"integer","description":"Timing element in microseconds (default 400)"},` +
			`"preset":{"type":"string","description":"Flipper preset name (defaults to OOK 650 async for ISM bands)"}` +
			`}}`),
		Required:  []string{"path", "frequency", "bit_count", "start_key", "end_key"},
		Risk:      risk.Medium,
		Group:     GroupFlipperSubGHz,
		AgentOnly: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			path := str(p, "path")
			if path == "" {
				return "", fmt.Errorf("path required")
			}
			startKey := uint64(intOr(p, "start_key", 0))
			endKey := uint64(intOr(p, "end_key", 0))
			bitCount := intOr(p, "bit_count", 0)

			raw, err := fileformat.BuildSubBruteforce(fileformat.SubBruteforceParams{
				Frequency: uint32(intOr(p, "frequency", 0)),
				BitCount:  bitCount,
				StartKey:  startKey,
				EndKey:    endKey,
				TE:        intOr(p, "te", 0),
				Preset:    str(p, "preset"),
			})
			if err != nil {
				return "", err
			}
			d.SnapshotBeforeWrite(ctx, path)
			if err := d.Flipper.WriteFileCtx(ctx, path, raw); err != nil {
				return "", fmt.Errorf("write %s: %w", path, err)
			}
			count := endKey - startKey + 1
			return fmt.Sprintf("built %d-byte bruteforce .sub (%d keys × %d bits) → %s",
				len(raw), count, bitCount, path), nil
		},
	})

	Register(Spec{
		Name: "subghz_freq_sweep",
		Description: "Generate multiple RAW .sub files — one per frequency — covering the same Princeton-family " +
			"key range. Use for multi-band reconnaissance (e.g. the same 24-bit sweep across 315/433.92/868/915 MHz " +
			"ISM bands) in one call instead of four. Files are named sweep_<freq>.sub under the destination directory.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"dir":{"type":"string","description":"Destination directory on SD card, e.g. /ext/subghz/sweep/"},` +
			`"frequencies":{"type":"array","description":"Array of frequencies in Hz, e.g. [315000000, 433920000, 868350000]. Max 16 per call."},` +
			`"bit_count":{"type":"integer","description":"Protocol bit length (24 for Princeton-family)"},` +
			`"start_key":{"type":"integer","description":"Inclusive start of the key range"},` +
			`"end_key":{"type":"integer","description":"Inclusive end of the key range"},` +
			`"te":{"type":"integer","description":"Timing element in microseconds (default 400)"},` +
			`"preset":{"type":"string","description":"Flipper preset name"}` +
			`}}`),
		Required:  []string{"dir", "frequencies", "bit_count", "start_key", "end_key"},
		Risk:      risk.Medium,
		Group:     GroupFlipperSubGHz,
		AgentOnly: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			dir := str(p, "dir")
			if dir == "" {
				return "", fmt.Errorf("dir required")
			}
			freqs, ok := p["frequencies"].([]interface{})
			if !ok || len(freqs) == 0 {
				return "", fmt.Errorf("frequencies must be a non-empty array")
			}
			freqU32 := make([]uint32, 0, len(freqs))
			for i, v := range freqs {
				f, ok := v.(float64)
				if !ok {
					return "", fmt.Errorf("frequencies[%d] must be a number", i)
				}
				freqU32 = append(freqU32, uint32(f))
			}
			built, err := fileformat.BuildSubBruteforceSweep(fileformat.SubFreqSweepParams{
				Frequencies: freqU32,
				BitCount:    intOr(p, "bit_count", 0),
				StartKey:    uint64(intOr(p, "start_key", 0)),
				EndKey:      uint64(intOr(p, "end_key", 0)),
				TE:          intOr(p, "te", 0),
				Preset:      str(p, "preset"),
			})
			if err != nil {
				return "", err
			}
			dir = strings.TrimRight(dir, "/")
			var summary []string
			for freq, raw := range built {
				path := fmt.Sprintf("%s/sweep_%d.sub", dir, freq)
				d.SnapshotBeforeWrite(ctx, path)
				if err := d.Flipper.WriteFileCtx(ctx, path, raw); err != nil {
					return "", fmt.Errorf("write %s: %w", path, err)
				}
				summary = append(summary, fmt.Sprintf("%s (%d B)", path, len(raw)))
			}
			return fmt.Sprintf("built %d bruteforce files:\n%s", len(built), strings.Join(summary, "\n")), nil
		},
	})

	Register(Spec{
		Name: "subghz_build",
		Description: "Construct a valid Flipper .sub file from parameters and write it to the SD card. " +
			"Use when you know the exact frequency, protocol, and key hex — safer than generate_subghz " +
			"for replaying a captured key. Returns the written path. Output is verified before write; " +
			"high/critical verdicts block unless verify_bypass=true.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"path":{"type":"string","description":"Destination on SD card, e.g. /ext/subghz/remote.sub"},` +
			`"frequency":{"type":"integer","description":"Frequency in Hz, e.g. 433920000"},` +
			`"protocol":{"type":"string","description":"Protocol name: Princeton, CAME, Keeloq, etc. Omit for RAW data."},` +
			`"preset":{"type":"string","description":"Flipper preset name (defaults to OOK 650 async for ISM bands)."},` +
			`"key_hex":{"type":"string","description":"Space-separated hex bytes, e.g. '00 00 00 1A 2B 3C 4D 00'"},` +
			`"bit":{"type":"integer","description":"Protocol bit length (e.g. 24 for Princeton)"},` +
			`"te":{"type":"integer","description":"Timing element in microseconds (e.g. 400)"},` +
			`"verify_bypass":{"type":"boolean","description":"Skip the verifier block on high/critical severity. Use only when the operator has reviewed the content."}` +
			`}}`),
		Required:  []string{"path", "frequency"},
		Risk:      risk.Medium,
		Group:     GroupFlipperSubGHz,
		AgentOnly: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			path := str(p, "path")
			if path == "" {
				return "", fmt.Errorf("path required")
			}
			raw, err := fileformat.BuildSub(fileformat.SubBuildParams{
				Frequency: uint32(intOr(p, "frequency", 0)),
				Protocol:  str(p, "protocol"),
				Preset:    str(p, "preset"),
				Key:       str(p, "key_hex"),
				Bit:       intOr(p, "bit", 0),
				TE:        intOr(p, "te", 0),
			})
			if err != nil {
				return "", err
			}
			summary, blockMsg := d.RunBuildVerification(ctx, "subghz", raw, boolOr(p, "verify_bypass", false))
			if blockMsg != "" {
				return blockMsg, nil
			}
			d.SnapshotBeforeWrite(ctx, path)
			if err := d.Flipper.WriteFileCtx(ctx, path, raw); err != nil {
				return "", fmt.Errorf("write %s: %w", path, err)
			}
			return fmt.Sprintf("built %d-byte .sub → %s\n%s", len(raw), path, summary), nil
		},
	})

	Register(Spec{
		Name: "rfid_build",
		Description: "Construct a valid Flipper .rfid file and write it to the SD card. Use to clone a known " +
			"LF protocol + hex payload onto a T5577 blank via rfid_write. Output is verified before write; " +
			"high/critical verdicts block unless verify_bypass=true.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"path":{"type":"string","description":"Destination on SD card, e.g. /ext/lfrfid/badge.rfid"},` +
			`"key_type":{"type":"string","description":"RFID protocol: EM4100, HIDProx, Indala, AWID, FDX-A, FDX-B"},` +
			`"data":{"type":"string","description":"Hex data, e.g. '1A 2B 3C 4D 5E' (spaces optional)"},` +
			`"verify_bypass":{"type":"boolean","description":"Skip the verifier block on high/critical severity."}` +
			`}}`),
		Required:  []string{"path", "key_type", "data"},
		Risk:      risk.Medium,
		Group:     GroupFlipperRFID,
		AgentOnly: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			path := str(p, "path")
			if path == "" {
				return "", fmt.Errorf("path required")
			}
			raw, err := fileformat.BuildRFID(fileformat.RFIDBuildParams{
				KeyType: str(p, "key_type"),
				Data:    str(p, "data"),
			})
			if err != nil {
				return "", err
			}
			summary, blockMsg := d.RunBuildVerification(ctx, "rfid", raw, boolOr(p, "verify_bypass", false))
			if blockMsg != "" {
				return blockMsg, nil
			}
			d.SnapshotBeforeWrite(ctx, path)
			if err := d.Flipper.WriteFileCtx(ctx, path, raw); err != nil {
				return "", fmt.Errorf("write %s: %w", path, err)
			}
			return fmt.Sprintf("built %d-byte .rfid → %s\n%s", len(raw), path, summary), nil
		},
	})

	Register(Spec{
		Name: "ir_build",
		Description: "Construct a valid Flipper .ir remote file from a list of IR signals. Each signal specifies " +
			"protocol+address+command (parsed mode) or frequency+duty_cycle+data (raw mode). Output is verified " +
			"before write; high/critical verdicts block unless verify_bypass=true.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"path":{"type":"string","description":"Destination on SD card, e.g. /ext/infrared/tv.ir"},` +
			`"name":{"type":"string","description":"Display label for the remote (defaults to 'generated')"},` +
			`"signals":{"type":"array","description":"Array of signal objects. Each: {name, type?, protocol?, address?, command?, frequency?, duty_cycle?, data?}"},` +
			`"verify_bypass":{"type":"boolean","description":"Skip the verifier block on high/critical severity."}` +
			`}}`),
		Required:  []string{"path", "signals"},
		Risk:      risk.Medium,
		Group:     GroupFlipperIR,
		AgentOnly: true,
		Handler: func(ctx context.Context, d *Deps, p map[string]any) (string, error) {
			path := str(p, "path")
			if path == "" {
				return "", fmt.Errorf("path required")
			}
			rawSignals, ok := p["signals"].([]interface{})
			if !ok || len(rawSignals) == 0 {
				return "", fmt.Errorf("signals must be a non-empty array")
			}
			signals := make([]fileformat.IRSignal, 0, len(rawSignals))
			for i, rs := range rawSignals {
				m, ok := rs.(map[string]interface{})
				if !ok {
					return "", fmt.Errorf("signals[%d] must be an object", i)
				}
				sig := fileformat.IRSignal{
					Name:      str(m, "name"),
					Type:      str(m, "type"),
					Protocol:  str(m, "protocol"),
					Address:   str(m, "address"),
					Command:   str(m, "command"),
					Frequency: intOr(m, "frequency", 0),
					DutyCycle: floatOr(m, "duty_cycle", 0),
				}
				if arr, ok := m["data"].([]interface{}); ok {
					sig.Data = make([]int, 0, len(arr))
					for _, v := range arr {
						if f, ok := v.(float64); ok {
							sig.Data = append(sig.Data, int(f))
						}
					}
				}
				signals = append(signals, sig)
			}
			raw, err := fileformat.BuildIR(fileformat.IRBuildParams{
				Name:    str(p, "name"),
				Signals: signals,
			})
			if err != nil {
				return "", err
			}
			summary, blockMsg := d.RunBuildVerification(ctx, "ir", raw, boolOr(p, "verify_bypass", false))
			if blockMsg != "" {
				return blockMsg, nil
			}
			d.SnapshotBeforeWrite(ctx, path)
			if err := d.Flipper.WriteFileCtx(ctx, path, raw); err != nil {
				return "", fmt.Errorf("write %s: %w", path, err)
			}
			return fmt.Sprintf("built %d-byte .ir (%d signals) → %s\n%s", len(raw), len(signals), path, summary), nil
		},
	})

	Register(Spec{
		Name: "nfc_build",
		Description: "Construct a valid Flipper .nfc file from parameters. UID-only files are valid for spoofing " +
			"badges; include ATQA/SAK/blocks for full MIFARE clones. Output is verified before write; high/critical " +
			"verdicts block unless verify_bypass=true.",
		Schema: json.RawMessage(`{"type":"object","properties":{` +
			`"path":{"type":"string","description":"Destination on SD card, e.g. /ext/nfc/badge.nfc"},` +
			`"device_type":{"type":"string","description":"Device type: 'Mifare Classic', 'Mifare Ultralight', 'NTAG213', etc."},` +
			`"uid":{"type":"string","description":"Tag UID as hex, e.g. 'AA BB CC DD'"},` +
			`"atqa":{"type":"string","description":"ATQA response hex, e.g. '0004'"},` +
			`"sak":{"type":"string","description":"SAK response hex, e.g. '08'"},` +
			`"mifare_type":{"type":"string","description":"Classic type label: '1K', '4K'"},` +
			`"blocks":{"type":"object","description":"Map of block index (string) to space-separated hex contents"},` +
			`"verify_bypass":{"type":"boolean","description":"Skip the verifier block on high/critical severity."}` +
			`}}`),
		Required:  []string{"path", "device_type", "uid"},
		Risk:      risk.Medium,
		Group:     GroupFlipperNFC,
		AgentOnly: true,
		Handler:   nfcBuildHandler,
	})
}

func nfcBuildHandler(ctx context.Context, d *Deps, p map[string]any) (string, error) {
	path := str(p, "path")
	if path == "" {
		return "", fmt.Errorf("path required")
	}
	params := fileformat.NFCBuildParams{
		DeviceType: str(p, "device_type"),
		UID:        str(p, "uid"),
		ATQA:       str(p, "atqa"),
		SAK:        str(p, "sak"),
		MifareType: str(p, "mifare_type"),
		Blocks:     map[int]string{},
	}
	if blocks, ok := p["blocks"].(map[string]interface{}); ok {
		for k, v := range blocks {
			idx := 0
			if _, err := fmt.Sscanf(k, "%d", &idx); err != nil {
				return "", fmt.Errorf("blocks key %q must be an integer", k)
			}
			if hex, ok := v.(string); ok {
				params.Blocks[idx] = hex
			}
		}
	}
	raw, err := fileformat.BuildNFC(params)
	if err != nil {
		return "", err
	}
	summary, blockMsg := d.RunBuildVerification(ctx, "nfc", raw, boolOr(p, "verify_bypass", false))
	if blockMsg != "" {
		return blockMsg, nil
	}
	d.SnapshotBeforeWrite(ctx, path)
	if err := d.Flipper.WriteFileCtx(ctx, path, raw); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return fmt.Sprintf("built %d-byte .nfc → %s\n%s", len(raw), path, summary), nil
}
