// objectid.go — host-side MongoDB ObjectId decoder Spec, delegating to
// internal/objectid.
//
// Wrap-vs-native: native — an ObjectId is 12 bytes with a fixed BSON layout
// (4-byte BE timestamp + 5-byte random + 3-byte counter); decoding is hex + a
// uint32 read. Surfaces the embedded creation timestamp (the recon value) —
// the completion of the opaque-hex ObjectId in mongodb_decode / bson_decode.
// Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/objectid"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(objectIDDecodeSpec)
}

var objectIDDecodeSpec = Spec{
	Name: "objectid_decode",
	Description: "Decode a MongoDB ObjectId into its embedded fields — most usefully its **creation " +
		"timestamp**. A 12-byte ObjectId is the default `_id` of every MongoDB document and is not opaque: " +
		"its first four bytes are the Unix-second creation time. ObjectIds leak into URLs, REST API " +
		"parameters, logs, and exported documents, so a captured ObjectId reveals **when its record was " +
		"created** — and the trailing 3-byte counter supports record-enumeration / timing inference. The " +
		"MongoDB analogue of `uuid_decode`, and the completion of the ObjectId rendering in `mongodb_decode` " +
		"/ `bson_decode` (which surface it only as raw hex).\n\n" +
		"Returns the **timestamp** (UTC + unix seconds), the 5-byte per-process **random** value (hex), and " +
		"the 3-byte **counter** (integer). The legacy pre-3.4 machine-id/process-id split of the middle " +
		"bytes is deprecated and deliberately not asserted (it would be a confidently-wrong reading on a " +
		"modern ObjectId). Accepts a bare 24-hex string or an `ObjectId(\"…\")` / quoted wrapper. A string " +
		"that is not exactly 24 hex digits is rejected. No network, no device, transmits nothing, so it is " +
		"Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (identifier info-leak triage — companion to mongodb_decode / " +
		"bson_decode and uuid_decode). Wrap-vs-native: native — BSON-spec field extraction, stdlib only, no " +
		"new go.mod dep. Anchored to pymongo `ObjectId.generation_time`: 507f1f77bcf86cd799439011 → " +
		"2012-10-17T21:13:27Z.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"objectid":{"type":"string","description":"A MongoDB ObjectId — 24 hex digits, optionally wrapped as ObjectId(\"…\") or quoted."}
		},
		"required":["objectid"]
	}`),
	Required:  []string{"objectid"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   objectIDDecodeHandler,
}

func objectIDDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	in := strings.TrimSpace(str(p, "objectid"))
	if in == "" {
		return "", fmt.Errorf("objectid_decode: 'objectid' is required")
	}
	res, err := objectid.Decode(in)
	if err != nil {
		return "", fmt.Errorf("objectid_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
