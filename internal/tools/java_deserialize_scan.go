// java_deserialize_scan.go — host-side Java serialized-object triage Spec,
// delegating to internal/javaser.
//
// Wrap-vs-native: native — a recursive-descent parser of the Java Object
// Serialization Stream Protocol, stdlib only, no new go.mod dep. Extracts the
// class names + flags ysoserial gadget classes without ever deserializing
// (readObject would be the exploit). Offline; no network or device.

package tools

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/javaser"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(javaDeserializeScanSpec)
}

var javaDeserializeScanSpec = Spec{
	Name: "java_deserialize_scan",
	Description: "Triage a **Java serialized-object** stream for **deserialization-RCE** indicators. Java " +
		"deserialization is one of the highest-impact RCE classes: an app that calls " +
		"`ObjectInputStream.readObject()` on attacker data can be driven to code execution through a **gadget " +
		"chain** of classes already on its classpath (ysoserial: **CommonsCollections**, the xalan " +
		"**TemplatesImpl**, the reflection **AnnotationInvocationHandler**, BeanComparator, C3P0, Groovy, …). A " +
		"serialized blob (magic `0xACED`) turns up in HTTP **cookies / parameters**, **RMI / JMX / JNDI / T3** " +
		"traffic, and `.ser` files. This parses the wire format per the JDK spec and surfaces the **version**, the " +
		"**top-level type**, **every class name** in the stream, a sample of the embedded **strings**, and — " +
		"**flagged** — any class matching the **known gadget / dangerous set**. The safe way to answer *what does " +
		"this instantiate?* is to parse the bytes — this **never calls readObject**, never loads a class, never " +
		"runs a constructor.\n\n" +
		"**No confidently-wrong output**: the grammar is parsed deterministically; an unsupported construct or a " +
		"short buffer **stops the walk** (`truncated:true` + a note) and returns the correctly-parsed class names " +
		"found so far — it never fabricates a class name or guesses past an ambiguity; recursion is depth-capped " +
		"against a **serialization bomb**. A gadget hit is a strong RCE signal; a clean result is **not** a " +
		"guarantee of safety (custom/unknown gadgets exist). No network, no device, transmits nothing — Low risk. " +
		"Pairs with the malware-triage suite.\n\n" +
		"Provide the serialized stream **base64-encoded** (or hex — it is binary). Source: " +
		"docs/catalog/gap-analysis.md (deserialization triage). Wrap-vs-native: native — a parser of the " +
		"documented wire format, stdlib only, no new go.mod dep; anchored to real javac/ObjectOutputStream " +
		"streams.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"data":{"type":"string","description":"The Java serialized stream, base64-encoded (or hex). It is binary."}
		},
		"required":["data"]
	}`),
	Required:  []string{"data"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   javaDeserializeScanHandler,
}

func javaDeserializeScanHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "data"))
	if in == "" {
		return "", fmt.Errorf("java_deserialize_scan: 'data' is required")
	}
	raw, err := javaBytes(in)
	if err != nil {
		return "", fmt.Errorf("java_deserialize_scan: %w", err)
	}
	res, err := javaser.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("java_deserialize_scan: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}

// javaBytes resolves the input to bytes: base64 first, then a hex fallback (the
// stream is binary and is commonly pasted as either).
func javaBytes(in string) ([]byte, error) {
	compact := strings.Join(strings.Fields(in), "")
	if b, err := base64.StdEncoding.DecodeString(compact); err == nil && len(b) >= 2 && b[0] == 0xAC && b[1] == 0xED {
		return b, nil
	}
	if b, err := hex.DecodeString(strings.TrimPrefix(compact, "0x")); err == nil && len(b) >= 2 && b[0] == 0xAC && b[1] == 0xED {
		return b, nil
	}
	// Fall back to base64 (surfaces a clear error if it is neither).
	b, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return nil, fmt.Errorf("input is neither valid base64 nor hex")
	}
	return b, nil
}
