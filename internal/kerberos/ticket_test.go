// SPDX-License-Identifier: AGPL-3.0-or-later

package kerberos

import (
	"strings"
	"testing"
)

// ticketDER is a Kerberos Ticket ([APPLICATION 1]) built by the authoritative
// impacket library: tkt-vno 5, realm CORP.LOCAL, sname HTTP/web.corp.local
// (name-type 3), enc-part etype 23 (RC4) kvno 2. This is the shape a
// ccache_decode ticket blob has.
const ticketDER = "615c305aa003020105a10c1b0a434f52502e4c4f43414ca221301fa003020103a11830161b04485454501b0e7765622e636f72702e6c6f63616ca3223020a003020117a103020102a214041201020304656e637279707465642d626c6f62"

func TestDecodeBareTicket(t *testing.T) {
	r, err := Decode(ticketDER)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageType != 1 || r.MessageTypeName != "Ticket" {
		t.Errorf("message type = %d %q, want 1 Ticket", r.MessageType, r.MessageTypeName)
	}
	tk := r.Ticket
	if tk == nil {
		t.Fatal("Ticket is nil")
	}
	if tk.TktVno != 5 {
		t.Errorf("tkt-vno = %d, want 5", tk.TktVno)
	}
	if tk.Realm != "CORP.LOCAL" {
		t.Errorf("realm = %q, want CORP.LOCAL", tk.Realm)
	}
	if tk.ServiceName != "HTTP/web.corp.local" {
		t.Errorf("service name = %q, want HTTP/web.corp.local", tk.ServiceName)
	}
	if tk.EncType != 23 {
		t.Errorf("enc type = %d, want 23", tk.EncType)
	}
	if !strings.Contains(tk.EncTypeName, "rc4") {
		t.Errorf("enc type name = %q, want rc4", tk.EncTypeName)
	}
	if tk.KVNO != 2 {
		t.Errorf("kvno = %d, want 2", tk.KVNO)
	}
	if !strings.Contains(tk.Note, "Kerberoastable") {
		t.Errorf("RC4 ticket should be flagged Kerberoastable, note = %q", tk.Note)
	}
}
