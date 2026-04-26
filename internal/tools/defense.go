// defense.go — passive blue-team Specs.
//
// Currently exposes a single Spec, defense_classify_advertisement, that
// runs the package internal/defense's stateless classifier on a single
// captured BLE advertisement payload. This is the building block for
// active scanning — operators can either (a) feed advertisements
// observed by other tooling (Marauder sniffer, host BLE scanner) into
// this Spec, or (b) wire it into a continuous loop driven from agent
// code.
//
// The matching live-scan Spec will land once the platform-gated BLE
// listener (internal/defense/scanner.go) is verified on real hardware;
// it has the same classifier core but adds an event loop. For now the
// stateless analyser is enough to demonstrate the detection logic and
// gives operators a way to score a captured pcap or vendor dump
// off-line.

package tools

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/defense"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(defenseClassifyAdSpec)
}

var defenseClassifyAdSpec = Spec{
	Name:        "defense_classify_advertisement",
	Description: "Classify one captured BLE advertisement against the Wall-of-Flippers heuristic ruleset (Apple Continuity spam, Microsoft Swift Pair malformed, Samsung sentinel model-id, Google Fast Pair repeated-byte, Flipper service UUID). Returns matched signatures with descriptions. Stateless — for cross-advertisement detection (high-frequency MAC rotation) call this from a loop and aggregate. Read-only, no I/O.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"address":{"type":"string","description":"Source MAC, AA:BB:CC:DD:EE:FF (optional)"},
			"local_name":{"type":"string","description":"GAP local name (optional)"},
			"service_uuids":{"type":"array","items":{"type":"string"},"description":"Advertised service UUIDs (any common form: 0xfe60, fe60, full 128-bit)"},
			"manufacturer_data":{"type":"object","description":"Map of manufacturer ID (decimal int as string) to hex-encoded payload, e.g. {\"76\":\"42010203\"} for Apple. Decimal keys avoid JSON typing issues."},
			"manufacturer_data_b64":{"type":"object","description":"Same as manufacturer_data but values are base64-encoded raw bytes."},
			"service_data":{"type":"object","description":"Map of service UUID (decimal int as string) to hex-encoded payload."}
		}
	}`),
	Required:  nil,
	Risk:      risk.Low,
	Group:     GroupMetaUtil,
	AgentOnly: false,
	Handler:   defenseClassifyAdHandler,
}

func defenseClassifyAdHandler(_ context.Context, _ *Deps, args map[string]any) (string, error) {
	ad, err := parseAdvertisement(args)
	if err != nil {
		return "", fmt.Errorf("defense_classify_advertisement: %w", err)
	}
	matches := defense.Classify(ad)
	out := map[string]any{
		"address":     ad.Address,
		"matches":     formatMatches(matches),
		"match_count": len(matches),
		"verdict":     verdictFor(matches),
	}
	body, _ := json.Marshal(out)
	return string(body), nil
}

func parseAdvertisement(args map[string]any) (defense.Advertisement, error) {
	ad := defense.Advertisement{
		Address:   strings.ToUpper(str(args, "address")),
		LocalName: str(args, "local_name"),
	}

	if uuids, ok := args["service_uuids"].([]any); ok {
		for _, v := range uuids {
			if s, ok := v.(string); ok {
				ad.ServiceUUIDs = append(ad.ServiceUUIDs, s)
			}
		}
	}

	if md, ok := args["manufacturer_data"].(map[string]any); ok {
		ad.ManufacturerData = map[uint16][]byte{}
		for k, v := range md {
			id, err := parseManufacturerID(k)
			if err != nil {
				return ad, fmt.Errorf("manufacturer_data key %q: %w", k, err)
			}
			s, _ := v.(string)
			b, err := hex.DecodeString(s)
			if err != nil {
				return ad, fmt.Errorf("manufacturer_data[%s] not hex: %w", k, err)
			}
			ad.ManufacturerData[id] = b
		}
	}
	if md, ok := args["manufacturer_data_b64"].(map[string]any); ok {
		if ad.ManufacturerData == nil {
			ad.ManufacturerData = map[uint16][]byte{}
		}
		for k, v := range md {
			id, err := parseManufacturerID(k)
			if err != nil {
				return ad, fmt.Errorf("manufacturer_data_b64 key %q: %w", k, err)
			}
			s, _ := v.(string)
			b, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				return ad, fmt.Errorf("manufacturer_data_b64[%s] not base64: %w", k, err)
			}
			ad.ManufacturerData[id] = b
		}
	}

	if sd, ok := args["service_data"].(map[string]any); ok {
		ad.ServiceData = map[uint16][]byte{}
		for k, v := range sd {
			id, err := parseManufacturerID(k)
			if err != nil {
				return ad, fmt.Errorf("service_data key %q: %w", k, err)
			}
			s, _ := v.(string)
			b, err := hex.DecodeString(s)
			if err != nil {
				return ad, fmt.Errorf("service_data[%s] not hex: %w", k, err)
			}
			ad.ServiceData[id] = b
		}
	}

	return ad, nil
}

func parseManufacturerID(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		var n uint64
		_, err := fmt.Sscanf(s[2:], "%x", &n)
		if err != nil {
			return 0, err
		}
		if n > 0xFFFF {
			return 0, fmt.Errorf("value %s exceeds uint16", s)
		}
		return uint16(n), nil
	}
	var n uint64
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil {
		return 0, err
	}
	if n > 0xFFFF {
		return 0, fmt.Errorf("value %s exceeds uint16", s)
	}
	return uint16(n), nil
}

func formatMatches(matches []defense.Match) []map[string]string {
	out := make([]map[string]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, map[string]string{
			"signature":   string(m.Signature),
			"description": m.Description,
			"source_mac":  m.SourceMAC,
		})
	}
	return out
}

func verdictFor(matches []defense.Match) string {
	if len(matches) == 0 {
		return "clean"
	}
	for _, m := range matches {
		switch m.Signature {
		case defense.SigAppleContinuitySpam,
			defense.SigSwiftPairMalformed,
			defense.SigSamsungWatchSpam,
			defense.SigGoogleFastPairSpam,
			defense.SigHighFrequencyMACRotation:
			return "spam_attack_likely"
		}
	}
	return "review_needed"
}
