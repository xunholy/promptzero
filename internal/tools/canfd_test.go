package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestCanbusFDDecodeHandler_FDFrame feeds a CAN-FD candump frame and
// confirms the Spec handler decodes it into JSON the agent can render,
// including the J1939 decomposition for the 29-bit ID.
func TestCanbusFDDecodeHandler_FDFrame(t *testing.T) {
	// Priority 3, PF=0xF0, PS=0x04 (EEC1 PGN 0xF004), SA=0x00; FD flags
	// nibble 1 (BRS), 8 data bytes.
	out, err := canbusFDDecodeHandler(context.Background(), nil,
		map[string]any{"frame": "0CF00400##10001020304050607"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var got struct {
		Format    string `json:"format"`
		IDDecimal uint32 `json:"id_decimal"`
		Extended  bool   `json:"extended"`
		FDF       bool   `json:"fdf"`
		BRS       bool   `json:"brs"`
		DLC       int    `json:"dlc"`
		J1939     *struct {
			PGN  int    `json:"pgn"`
			Kind string `json:"kind"`
		} `json:"j1939"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out)
	}
	if !got.FDF || !got.BRS {
		t.Errorf("FDF=%v BRS=%v; want both true\n%s", got.FDF, got.BRS, out)
	}
	if !got.Extended {
		t.Errorf("Extended = false; want true for 29-bit ID")
	}
	if got.J1939 == nil || got.J1939.PGN != 0xF004 {
		t.Errorf("J1939 PGN = %v; want 0xF004\n%s", got.J1939, out)
	}
}

func TestCanbusFDDecodeHandler_ClassicFrame(t *testing.T) {
	out, err := canbusFDDecodeHandler(context.Background(), nil,
		map[string]any{"frame": "123#DEADBEEF"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"format": "CAN 2.0 (classic)"`) {
		t.Errorf("expected classic-CAN format in JSON:\n%s", out)
	}
}

func TestCanbusFDDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := canbusFDDecodeHandler(context.Background(), nil, map[string]any{})
	if err == nil {
		t.Fatal("want error for missing frame")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("err = %v; want 'required'", err)
	}
}
