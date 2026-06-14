// php_unserialize_scan.go — host-side PHP serialized-object triage Spec,
// delegating to internal/phpserialize.
//
// Wrap-vs-native: native — a recursive-descent parser of the documented PHP
// serialize() text grammar, stdlib only, no new go.mod dep. Surfaces the object
// tree + class names + flags PHP Object Injection gadget classes without ever
// calling unserialize(). Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/phpserialize"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(phpUnserializeScanSpec)
}

var phpUnserializeScanSpec = Spec{
	Name: "php_unserialize_scan",
	Description: "Triage a **PHP `serialize()`** blob for **PHP Object Injection (POI)** indicators. PHP's " +
		"serialize() / unserialize() is the wire format behind **session files, cookies, caches**, and framework " +
		"tokens; if an app calls `unserialize()` on attacker data, an attacker can **inject an arbitrary object** " +
		"(`O:…`) whose **magic methods** (`__wakeup` / `__destruct` / `__toString`) fire a **POP chain** — the " +
		"**phpggc** gadget families (**Monolog / Guzzle / Laravel-Illuminate / Symfony / Doctrine / WordPress / " +
		"…**) turn that into RCE / file-write / SSRF. This parses the documented grammar — N / b / i / d / s " +
		"(byte-length string) / a (array) / O (object) / C (custom-Serializable) / E (enum) / r,R (reference) — " +
		"into a JSON value tree, collects every **object class name**, de-mangles **private** (`\\0Class\\0prop`) " +
		"and **protected** (`\\0*\\0prop`) property keys, **flags** any class in the known gadget set, and notes " +
		"that *any* serialized object reaching `unserialize()` is an **object-injection surface**. It **never " +
		"calls unserialize**, never instantiates anything.\n\n" +
		"**No confidently-wrong output**: the grammar is parsed deterministically; a malformed or unsupported " +
		"construct **stops the parse** (`truncated:true` + a note) and returns the correctly-parsed tree so far — " +
		"it never guesses past an ambiguity; recursion is depth-capped against a nested-object bomb. A gadget hit " +
		"is a strong POI/RCE signal; a clean result is **not** a guarantee of safety (custom gadgets exist). No " +
		"network, no device, transmits nothing — Low risk. Pairs with `java_deserialize_scan` / `pickle_decode`.\n\n" +
		"Provide the PHP serialized string as text. Source: docs/catalog/gap-analysis.md (deserialization " +
		"triage). Wrap-vs-native: native — a parser of the documented text grammar, stdlib only, no new go.mod " +
		"dep; anchored to hand-built + phpggc-style vectors.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"data":{"type":"string","description":"The PHP serialize() string (e.g. from a cookie, session file, or cache)."}
		},
		"required":["data"]
	}`),
	Required:  []string{"data"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   phpUnserializeScanHandler,
}

func phpUnserializeScanHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := str(p, "data")
	if strings.TrimSpace(in) == "" {
		return "", fmt.Errorf("php_unserialize_scan: 'data' is required")
	}
	res, err := phpserialize.Decode([]byte(in))
	if err != nil {
		return "", fmt.Errorf("php_unserialize_scan: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
