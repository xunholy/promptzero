// SPDX-License-Identifier: AGPL-3.0-or-later

package keytab

import (
	"strings"
	"testing"
)

// ktHex is a v0x0502 keytab built per the MIT spec and confirmed by
// `ktutil rkt … / list -e -t` to list:
//
//	KVNO 5  HTTP/web.example.com@EXAMPLE.COM (aes256-cts-hmac-sha1-96)
//
// (principal HTTP/web.example.com, realm EXAMPLE.COM, name-type 3 SRV_HST,
// timestamp 1700000000, etype 18, 32-byte key 0x00..0x1f).
const ktHex = "0502000000530002000b4558414d504c452e434f4d000448545450000f7765622e6578616d706c652e636f6d000000036553f1000500120020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func TestDecodeKtutilVector(t *testing.T) {
	r, err := Decode(ktHex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != "0x0502" {
		t.Errorf("version = %q", r.Version)
	}
	if len(r.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(r.Entries))
	}
	e := r.Entries[0]
	if e.Principal != "HTTP/web.example.com@EXAMPLE.COM" {
		t.Errorf("principal = %q", e.Principal)
	}
	if e.Realm != "EXAMPLE.COM" {
		t.Errorf("realm = %q", e.Realm)
	}
	if len(e.Components) != 2 || e.Components[0] != "HTTP" || e.Components[1] != "web.example.com" {
		t.Errorf("components = %v", e.Components)
	}
	if e.NameType != 3 || e.NameTypeName != "KRB5_NT_SRV_HST" {
		t.Errorf("name type = %d %q", e.NameType, e.NameTypeName)
	}
	if e.KVNO != 5 {
		t.Errorf("kvno = %d, want 5", e.KVNO)
	}
	if e.EnctypeID != 18 || e.EnctypeName != "aes256-cts-hmac-sha1-96" {
		t.Errorf("enctype = %d %q", e.EnctypeID, e.EnctypeName)
	}
	if e.TimestampUnix != 1700000000 {
		t.Errorf("timestamp = %d", e.TimestampUnix)
	}
	if e.KeyLength != 32 || e.KeyHex != "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" {
		t.Errorf("key = %d %q", e.KeyLength, e.KeyHex)
	}
}

// TestRC4Note flags an RC4 (etype 23) key as the NT hash.
func TestRC4Note(t *testing.T) {
	// Same entry shape but etype 23 + 16-byte RC4 key. Rebuild the bytes:
	// version + size + numComp(1) + realm + comp + nameType + ts + kvno + etype23 + key16.
	// numComp=1, realm "R" (1 byte), comp "svc" (3 bytes).
	// body: 0001 0001 52 0003 737663 00000001 00000000 01 0017 0010 <16 bytes>
	body := "0001" + "000152" + "0003737663" + "00000001" + "00000000" + "01" + "0017" + "0010" + "ffeeddccbbaa99887766554433221100"
	size := "00000027" // 0x27 = 39 bytes of body
	kt := "0502" + size + body
	r, err := Decode(kt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	e := r.Entries[0]
	if e.EnctypeID != 23 {
		t.Fatalf("etype = %d, want 23", e.EnctypeID)
	}
	if !strings.Contains(e.Note, "NT hash") {
		t.Errorf("RC4 entry should flag the NT hash, note = %q", e.Note)
	}
	if e.Principal != "svc@R" {
		t.Errorf("principal = %q", e.Principal)
	}
}

// TestMinInt32DeletedSize pins the fix for a fuzz-found panic: an entry size of
// 0x80000000 (MinInt32) on the deleted-entry path negated back to a negative
// value and drove the offset negative → slice out of range. It must now be
// rejected, not crash (regression for seed 0f5a09e00d9307b7).
func TestMinInt32DeletedSize(t *testing.T) {
	if _, err := Decode("050280000000"); err == nil {
		t.Error("MinInt32 deleted-entry size must be rejected, not panic")
	}
}

func TestRejectsMalformed(t *testing.T) {
	for _, c := range []string{
		"",
		"05",           // too short
		"0501deadbeef", // legacy version rejected
		"9999deadbeef", // wrong version
		"0502ffffffff", // entry size huge / overrun
		"050200000020" + "0002000b4558414d504c45", // entry truncated mid-body
	} {
		if _, err := Decode(c); err == nil {
			t.Errorf("Decode(%q): want error, got nil", c)
		}
	}
}
