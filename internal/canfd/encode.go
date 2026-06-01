// SPDX-License-Identifier: AGPL-3.0-or-later

package canfd

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// EncodeRequest describes a CAN / CAN-FD frame to build in the SocketCAN
// candump grammar.
type EncodeRequest struct {
	ID        uint32 // CAN identifier (11-bit standard or 29-bit extended)
	Extended  bool   // 29-bit extended identifier
	FD        bool   // CAN-FD frame (## grammar)
	BRS       bool   // CAN-FD bit-rate switch (FD only)
	ESI       bool   // CAN-FD error-state indicator (FD only)
	RTR       bool   // classic remote frame (classic only)
	RemoteDLC int    // requested DLC for a remote frame (0..8)
	Data      []byte // payload (ignored for RTR)
}

// Encode builds the SocketCAN candump frame string for a CAN / CAN-FD frame
// — the inverse of Decode. The identifier is rendered the way candump pads
// it (3 hex chars for standard, 8 for extended) so Decode infers the width
// back correctly; classic frames use "ID#data" (or "ID#R"/"ID#Rn" for a
// remote frame) and CAN-FD frames use "ID##<flags-nibble><data>" with the
// BRS/ESI flags in the nibble. The result is exactly what canbus_inject
// sends and round-trips through Decode.
func Encode(r EncodeRequest) (string, error) {
	if r.ID > 0x1FFFFFFF {
		return "", fmt.Errorf("canfd: identifier 0x%X exceeds the 29-bit CAN range", r.ID)
	}
	if !r.Extended && r.ID > 0x7FF {
		return "", fmt.Errorf("canfd: identifier 0x%X needs the extended (29-bit) flag", r.ID)
	}

	var idStr string
	if r.Extended {
		idStr = fmt.Sprintf("%08X", r.ID)
	} else {
		idStr = fmt.Sprintf("%03X", r.ID)
	}

	if r.FD {
		if r.RTR {
			return "", fmt.Errorf("canfd: CAN-FD has no remote frames (RTR is classic-only)")
		}
		if _, ok := lengthToDLC(len(r.Data)); !ok {
			return "", fmt.Errorf("canfd: %d bytes is not a legal CAN-FD payload length (0-8, 12, 16, 20, 24, 32, 48, 64)", len(r.Data))
		}
		flags := 0
		if r.BRS {
			flags |= 0x1
		}
		if r.ESI {
			flags |= 0x2
		}
		return fmt.Sprintf("%s##%X%s", idStr, flags, strings.ToUpper(hex.EncodeToString(r.Data))), nil
	}

	// Classic CAN.
	if r.BRS || r.ESI {
		return "", fmt.Errorf("canfd: BRS/ESI are CAN-FD-only flags; set fd=true")
	}
	if r.RTR {
		if r.RemoteDLC < 0 || r.RemoteDLC > 8 {
			return "", fmt.Errorf("canfd: remote-frame DLC %d out of range (0..8)", r.RemoteDLC)
		}
		if r.RemoteDLC == 0 {
			return idStr + "#R", nil
		}
		return fmt.Sprintf("%s#R%X", idStr, r.RemoteDLC), nil
	}
	if len(r.Data) > 8 {
		return "", fmt.Errorf("canfd: classic CAN carries at most 8 data bytes (got %d); set fd=true for larger payloads", len(r.Data))
	}
	return idStr + "#" + strings.ToUpper(hex.EncodeToString(r.Data)), nil
}
