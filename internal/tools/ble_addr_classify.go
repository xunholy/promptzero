// ble_addr_classify.go — host-side BLE device-address classifier Spec,
// delegating to internal/ble.ClassifyAddress.
//
// Wrap-vs-native: native — classifying a BLE random address is reading the two
// most-significant bits of its most-significant octet (Bluetooth Core Vol 6
// Part B §1.3.2), an exact spec rule. It is the BLE counterpart of
// mac_classify and the offline analysis complement to BLE scanning: detecting
// a Resolvable Private Address (privacy/tracking-resistant) vs a static random
// (trackable) vs a public OUI address is a real device-privacy assessment.
// Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ble"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bleAddrClassifySpec)
}

var bleAddrClassifySpec = Spec{
	Name: "ble_addr_classify",
	Description: "Classify a BLE device address — the BLE counterpart of mac_classify, and the offline " +
		"analysis complement to BLE scanning. A BLE random address encodes its subtype in the two " +
		"most-significant bits of its most-significant octet (Bluetooth Core Vol 6 Part B §1.3.2): " +
		"0b11 = static random, 0b01 = resolvable private (RPA), 0b00 = non-resolvable private, " +
		"0b10 = reserved. This is the device-privacy / tracking-resistance signal — an RPA rotates and " +
		"is tracking-resistant, a static random is stable/trackable for the session, a public address " +
		"is an OUI-identifiable manufacturer EUI-48.\n\n" +
		"Because the address bytes alone do not say public vs random (that is the advertising PDU's " +
		"TxAdd bit), pass **address_type** (\"public\" / \"random\") to disambiguate. With \"random\" the " +
		"subtype is reported definitively; with \"public\" the OUI is surfaced; if omitted, the " +
		"random-address interpretation is reported with a note that a public address would make those " +
		"bits an OUI instead (no confidently-wrong output). The subtype bits are an exact spec rule, not " +
		"an enum guess.\n\n" +
		"Accepts ':' / '-' / '.' / no separators, case-insensitive. Offline transform — reads a string, " +
		"transmits nothing, so it is Low risk. Wrap-vs-native: native — bit test over a 6-byte address.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"address":{"type":"string","description":"48-bit BLE device address. ':' / '-' / '.' / no separators tolerated."},
			"address_type":{"type":"string","description":"Optional: \"public\" or \"random\" (from the advertising PDU's TxAdd bit). Omit if unknown.","enum":["public","random"]}
		},
		"required":["address"]
	}`),
	Required:  []string{"address"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bleAddrClassifyHandler,
}

func bleAddrClassifyHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "address")) == "" {
		return "", fmt.Errorf("ble_addr_classify: 'address' is required")
	}
	res, err := ble.ClassifyAddress(str(p, "address"), str(p, "address_type"))
	if err != nil {
		return "", fmt.Errorf("ble_addr_classify: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
