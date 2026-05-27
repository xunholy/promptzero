package zmtp

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// zmtpGreeting builds a well-formed 64-byte ZMTP 3.x greeting.
func zmtpGreeting(major, minor byte, mechanism string, asServer bool) []byte {
	b := make([]byte, greetingSize)
	b[0] = sigByte0
	// bytes 1-8: padding (already zero)
	b[9] = sigByte9
	b[10] = major
	b[11] = minor
	// mechanism: bytes 12-31, null-padded to 20 bytes
	copy(b[12:32], mechanism)
	if asServer {
		b[32] = 1
	}
	// bytes 33-63: filler zeros
	return b
}

// zmtpReadyCommand builds a ZMTP READY command frame with the given
// properties.  Properties is a list of (name, value) string pairs.
func zmtpReadyCommand(props [][2]string) []byte {
	// Build the body: 1-byte name_len + "READY" + properties.
	var propBuf []byte
	for _, p := range props {
		var entry []byte
		entry = binary.BigEndian.AppendUint32(entry, uint32(len(p[0])))
		entry = append(entry, []byte(p[0])...)
		entry = binary.BigEndian.AppendUint32(entry, uint32(len(p[1])))
		entry = append(entry, []byte(p[1])...)
		propBuf = append(propBuf, entry...)
	}

	name := "READY"
	body := append([]byte{byte(len(name))}, append([]byte(name), propBuf...)...)

	// flags byte: bit 2 set = command; short frame.
	flags := byte(0x04)
	frame := []byte{flags, byte(len(body))}
	frame = append(frame, body...)
	return frame
}

func TestDecode_ZMTP30_NULL(t *testing.T) {
	g := zmtpGreeting(3, 0, "NULL", false)
	r, err := Decode(hex.EncodeToString(g))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsGreeting {
		t.Error("expected IsGreeting=true")
	}
	if r.VersionMajor != 3 {
		t.Errorf("version_major=%d, want 3", r.VersionMajor)
	}
	if r.VersionMinor != 0 {
		t.Errorf("version_minor=%d, want 0", r.VersionMinor)
	}
	if r.Mechanism != "NULL" {
		t.Errorf("mechanism=%q, want NULL", r.Mechanism)
	}
	if r.MechanismName != "No authentication" {
		t.Errorf("mechanism_name=%q, want No authentication", r.MechanismName)
	}
	if r.AsServer {
		t.Error("as_server: want false")
	}
	if r.IsCleartextAuth {
		t.Error("NULL should not flag cleartext auth")
	}
}

func TestDecode_ZMTP31_PLAIN(t *testing.T) {
	g := zmtpGreeting(3, 1, "PLAIN", true)
	r, err := Decode(hex.EncodeToString(g))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsGreeting {
		t.Error("expected IsGreeting=true")
	}
	if r.VersionMajor != 3 {
		t.Errorf("version_major=%d, want 3", r.VersionMajor)
	}
	if r.VersionMinor != 1 {
		t.Errorf("version_minor=%d, want 1", r.VersionMinor)
	}
	if r.Mechanism != "PLAIN" {
		t.Errorf("mechanism=%q, want PLAIN", r.Mechanism)
	}
	if r.MechanismName != "Cleartext password" {
		t.Errorf("mechanism_name=%q, want Cleartext password", r.MechanismName)
	}
	if !r.AsServer {
		t.Error("as_server: want true")
	}
	if !r.IsCleartextAuth {
		t.Error("expected IsCleartextAuth=true for PLAIN")
	}
	if r.CleartextAuthFlag == "" {
		t.Error("expected non-empty CleartextAuthFlag for PLAIN")
	}
}

func TestDecode_ZMTP30_CURVE(t *testing.T) {
	g := zmtpGreeting(3, 0, "CURVE", false)
	r, err := Decode(hex.EncodeToString(g))
	if err != nil {
		t.Fatal(err)
	}
	if r.Mechanism != "CURVE" {
		t.Errorf("mechanism=%q, want CURVE", r.Mechanism)
	}
	if r.MechanismName != "CurveZMQ encryption" {
		t.Errorf("mechanism_name=%q, want CurveZMQ encryption", r.MechanismName)
	}
	if r.IsCleartextAuth {
		t.Error("CURVE should not flag cleartext auth")
	}
}

func TestDecode_GreetingPlusREADY(t *testing.T) {
	g := zmtpGreeting(3, 0, "NULL", false)
	ready := zmtpReadyCommand([][2]string{
		{"Socket-Type", "REQ"},
		{"Identity", "worker-1"},
	})
	pkt := append(g, ready...)

	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsGreeting {
		t.Error("expected IsGreeting=true")
	}
	if r.SocketType != "REQ" {
		t.Errorf("socket_type=%q, want REQ", r.SocketType)
	}
	if r.Identity != "worker-1" {
		t.Errorf("identity=%q, want worker-1", r.Identity)
	}
	if r.CommandName != "READY" {
		t.Errorf("command_name=%q, want READY", r.CommandName)
	}
}

func TestDecode_StandaloneREADYCommand(t *testing.T) {
	ready := zmtpReadyCommand([][2]string{
		{"Socket-Type", "PUB"},
	})
	r, err := Decode(hex.EncodeToString(ready))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsCommand {
		t.Error("expected IsCommand=true")
	}
	if r.CommandName != "READY" {
		t.Errorf("command_name=%q, want READY", r.CommandName)
	}
	if r.SocketType != "PUB" {
		t.Errorf("socket_type=%q, want PUB", r.SocketType)
	}
}

func TestDecode_RejectsEmpty(t *testing.T) {
	_, err := Decode("")
	if err == nil {
		t.Fatal("want error for empty input")
	}
}

func TestDecode_RejectsTruncated(t *testing.T) {
	// Only 5 bytes — valid hex but not enough to be a greeting or frame.
	_, err := Decode("ff00000000")
	if err == nil {
		t.Fatal("want error for truncated greeting-like input")
	}
}

func TestDecode_ZMTP20_SocketType(t *testing.T) {
	// ZMTP 2.0 greeting: 0xFF + 8 zeros + 0x7F + version=0x01 + socket_type=3 (REQ)
	b := make([]byte, 12)
	b[0] = sigByte0
	b[9] = sigByte9
	b[10] = 0x01 // ZMTP 2.0 version
	b[11] = 0x03 // REQ
	r, err := Decode(hex.EncodeToString(b))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsGreeting {
		t.Error("expected IsGreeting=true")
	}
	if r.SocketType != "REQ" {
		t.Errorf("socket_type=%q, want REQ", r.SocketType)
	}
}
