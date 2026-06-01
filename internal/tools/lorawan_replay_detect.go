// lorawan_replay_detect.go — host-side defensive LoRaWAN replay /
// frame-counter-reuse detector Spec, delegating to internal/lorawan.
//
// Wrap-vs-native: native — the FCnt lives in the cleartext FHDR (no session
// key needed), and the LoRaWAN spec's mandatory FCnt check exists precisely
// to stop replay. Detecting reuse/regression is a deterministic transform
// over the (DevAddr, FCnt, direction) fields the lorawan decoder already
// extracts. Defensive sibling of subghz_rollback_detect / wifi_deauth_detect.

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/lorawan"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(lorawanReplayDetectSpec)
}

var lorawanReplayDetectSpec = Spec{
	Name: "lorawan_replay_detect",
	Description: "Defensive blue-team analysis of a SEQUENCE of decoded LoRaWAN data frames for replay " +
		"/ frame-counter reuse — the attack the spec's mandatory FCnt check exists to stop (replaying " +
		"captured uplinks; ABP devices that reset their counter). Feed the already-decoded FHDR fields " +
		"(DevAddr + FCnt + MType, e.g. from lorawan_decode) in observation order; the analyser does no " +
		"RF work and needs no session key — the frame counter is cleartext in the FHDR.\n\n" +
		"Frames are grouped by (DevAddr, direction) — uplink and downlink counters are independent, so " +
		"they are tracked separately (direction comes from the Up/Down MType). Two deterministic " +
		"signals, each an OBSERVATION with its benign explanation:\n" +
		" - **fcnt_reuse** (warning): a frame counter that reappears for a stream after the device " +
		"moved past it — the core replay signature. CONSECUTIVE equal counters are NOT flagged (a " +
		"confirmed frame is legitimately retransmitted with the same FCnt until acknowledged).\n" +
		" - **fcnt_regression** (warning): a counter below the running max for the stream. Benign " +
		"explanation: a 16-bit FCnt rollover (65535->0), an ABP device power-cycled, or frames fed out " +
		"of capture order.\n\n" +
		"Supply MType so uplink/downlink counters aren't cross-counted (a note is added if it's " +
		"missing). Pure offline analyser — no LoRa radio. Companion to lorawan_decode; the BLE/Sub-GHz " +
		"analogues are subghz_rollback_detect / wifi_deauth_detect. Wrap-vs-native: native — a pure " +
		"sequence transform over cleartext FHDR fields, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"frames":{
				"type":"array",
				"description":"Decoded LoRaWAN data frames in observation order.",
				"items":{
					"type":"object",
					"properties":{
						"dev_addr":{"type":"string","description":"4-byte device address (FHDR DevAddr); frames are grouped by it."},
						"fcnt":{"type":"integer","description":"Frame counter from the FHDR (the on-air 16-bit value)."},
						"mtype":{"type":"string","description":"Message type, e.g. UnconfirmedDataUp / ConfirmedDataDown — its Up/Down separates the independent counters."}
					},
					"required":["dev_addr","fcnt"]
				}
			}
		},
		"required":["frames"]
	}`),
	Required:  []string{"frames"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   lorawanReplayDetectHandler,
}

func lorawanReplayDetectHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	rawFrames, ok := p["frames"].([]any)
	if !ok || len(rawFrames) == 0 {
		return "", fmt.Errorf("lorawan_replay_detect: 'frames' must be a non-empty array of objects")
	}
	frames := make([]lorawan.ReplayFrame, 0, len(rawFrames))
	for i, rf := range rawFrames {
		m, ok := rf.(map[string]any)
		if !ok {
			return "", fmt.Errorf("lorawan_replay_detect: frames[%d] is not an object", i)
		}
		frames = append(frames, lorawan.ReplayFrame{
			DevAddr: str(m, "dev_addr"),
			FCnt:    intOf(m["fcnt"]),
			MType:   str(m, "mtype"),
		})
	}

	res, err := lorawan.AnalyzeReplay(frames)
	if err != nil {
		return "", fmt.Errorf("lorawan_replay_detect: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
