// SPDX-License-Identifier: AGPL-3.0-or-later

package ccache

import (
	"strings"
	"testing"
)

// ccHex is a v0x0504 ccache built per the MIT spec and confirmed by
// `klist -cf` to list:
//
//	Default principal: alice@EXAMPLE.COM
//	krbtgt/EXAMPLE.COM@EXAMPLE.COM   Flags: FRIA
//	(start 1700000000, end 1700003600, renew 1700086400)
//
// keyblock keytype 18, 32-byte key; ticket_flags 0x40e00000.
// The embedded ticket is a real impacket-built Ticket DER (sname
// HTTP/web.corp.local@CORP.LOCAL, etype 23) — `klist -cf` lists this same
// ccache including "Ticket server: HTTP/web.corp.local@CORP.LOCAL".
const ccHex = "0504000000000001000000010000000b4558414d504c452e434f4d00000005616c69636500000001000000010000000b4558414d504c452e434f4d00000005616c69636500000002000000020000000b4558414d504c452e434f4d000000066b72627467740000000b4558414d504c452e434f4d001200000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f6553f1006553f1006553ff10655542800040e0000000000000000000000000005e615c305aa003020105a10c1b0a434f52502e4c4f43414ca221301fa003020103a11830161b04485454501b0e7765622e636f72702e6c6f63616ca3223020a003020117a103020102a214041201020304656e637279707465642d626c6f6200000000"

func TestDecodeKlistVector(t *testing.T) {
	r, err := Decode(ccHex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != "0x0504" {
		t.Errorf("version = %q", r.Version)
	}
	if r.DefaultPrincipal != "alice@EXAMPLE.COM" {
		t.Errorf("default principal = %q", r.DefaultPrincipal)
	}
	if len(r.Credentials) != 1 {
		t.Fatalf("credentials = %d, want 1", len(r.Credentials))
	}
	c := r.Credentials[0]
	if c.Client != "alice@EXAMPLE.COM" {
		t.Errorf("client = %q", c.Client)
	}
	if c.Server != "krbtgt/EXAMPLE.COM@EXAMPLE.COM" {
		t.Errorf("server = %q", c.Server)
	}
	if c.KeyType != 18 || c.KeyTypeName != "aes256-cts-hmac-sha1-96" {
		t.Errorf("key type = %d %q", c.KeyType, c.KeyTypeName)
	}
	if c.KeyHex != "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" {
		t.Errorf("key = %q", c.KeyHex)
	}
	if c.TicketFlags != 0x40e00000 {
		t.Errorf("flags = 0x%08x", c.TicketFlags)
	}
	// klist showed Flags: FRIA = forwardable, renewable, initial, pre-authent.
	want := []string{"forwardable", "renewable", "initial", "pre-authent"}
	if strings.Join(c.TicketFlagNames, ",") != strings.Join(want, ",") {
		t.Errorf("flag names = %v, want %v", c.TicketFlagNames, want)
	}
	if c.StartTimeUTC != "2023-11-14T22:13:20Z" {
		t.Errorf("start = %q (want 2023-11-14T22:13:20Z = 1700000000)", c.StartTimeUTC)
	}
	if c.TicketLength == 0 || c.TicketHex == "" {
		t.Errorf("ticket should be surfaced: %+v", c)
	}
	if !strings.Contains(c.Note, "TGT") {
		t.Errorf("krbtgt credential should be flagged as a TGT, note = %q", c.Note)
	}
	// The embedded Ticket DER is chained into the Kerberos Ticket decoder.
	if c.InnerTicket == nil {
		t.Fatal("inner ticket should be decoded")
	}
	if c.InnerTicket.ServiceName != "HTTP/web.corp.local" || c.InnerTicket.Realm != "CORP.LOCAL" {
		t.Errorf("inner ticket sname/realm = %q / %q", c.InnerTicket.ServiceName, c.InnerTicket.Realm)
	}
	if c.InnerTicket.EncType != 23 {
		t.Errorf("inner ticket etype = %d, want 23", c.InnerTicket.EncType)
	}
}

func TestRejectsMalformed(t *testing.T) {
	for _, c := range []string{
		"",
		"05",           // too short
		"0501deadbeef", // legacy version rejected
		"9999deadbeef", // wrong version
		// valid header + default principal but a truncated credential:
		"0504000000000001000000010000000b4558414d504c452e434f4d00000005616c696365" + "0000",
	} {
		if _, err := Decode(c); err == nil {
			t.Errorf("Decode(%q): want error, got nil", c)
		}
	}
}
