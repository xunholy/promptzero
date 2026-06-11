package bluezkeys

import "testing"

func keyOf(t *testing.T, ks []Key, kind string) Key {
	t.Helper()
	for _, k := range ks {
		if k.Kind == kind {
			return k
		}
	}
	t.Fatalf("key %q not found in %+v", kind, ks)
	return Key{}
}

// A dual-mode info file (BR/EDR LinkKey + LE LTK/IRK), as BlueZ stores it.
const dualInfo = `[General]
Name=My Earbuds
Class=0x240404
SupportedTechnologies=BR/EDR;LE;
Trusted=true
AddressType=public

[LinkKey]
Key=00112233445566778899AABBCCDDEEFF
Type=4
PINLength=0

[LongTermKey]
Key=FEDCBA9876543210FEDCBA9876543210
Authenticated=0
EncSize=16
EDiv=12345
Rand=9876543210

[IdentityResolvingKey]
Key=0123456789ABCDEF0123456789ABCDEF
`

func TestDecode_Dual(t *testing.T) {
	r, err := Decode(dualInfo)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Name != "My Earbuds" || r.Transport != "dual" {
		t.Errorf("name=%q transport=%q", r.Name, r.Transport)
	}
	if len(r.Keys) != 3 {
		t.Fatalf("keys = %d, want 3 (%+v)", len(r.Keys), r.Keys)
	}
	lk := keyOf(t, r.Keys, "LinkKey")
	if lk.Value != "00112233445566778899AABBCCDDEEFF" || lk.Detail != "type=4" {
		t.Errorf("LinkKey = %+v", lk)
	}
	ltk := keyOf(t, r.Keys, "LongTermKey")
	if ltk.Value != "FEDCBA9876543210FEDCBA9876543210" || ltk.Detail == "" {
		t.Errorf("LTK = %+v", ltk)
	}
	irk := keyOf(t, r.Keys, "IdentityResolvingKey")
	if irk.Value != "0123456789ABCDEF0123456789ABCDEF" {
		t.Errorf("IRK = %+v", irk)
	}
}

// A pure-LE bond using the pre-5.x [SlaveLongTermKey] group name.
const leInfo = `[General]
Name=Heart Monitor
SupportedTechnologies=LE;
AddressType=random

[SlaveLongTermKey]
Key=AABBCCDDEEFF00112233445566778899
EncSize=16
EDiv=4321
Rand=1122334455

[IdentityResolvingKey]
Key=11112222333344445555666677778888
`

func TestDecode_LegacyPeripheralKey(t *testing.T) {
	r, err := Decode(leInfo)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Transport != "LE" {
		t.Errorf("transport = %q, want LE", r.Transport)
	}
	// [SlaveLongTermKey] must normalize to PeripheralLongTermKey.
	plt := keyOf(t, r.Keys, "PeripheralLongTermKey")
	if plt.Value != "AABBCCDDEEFF00112233445566778899" {
		t.Errorf("PeripheralLTK = %+v", plt)
	}
}

// A BR/EDR-only bond.
const bredrInfo = `[General]
Name=Car Stereo
SupportedTechnologies=BR/EDR;
[LinkKey]
Key=DEADBEEFDEADBEEFDEADBEEFDEADBEEF
Type=5
`

func TestDecode_BREDR(t *testing.T) {
	r, err := Decode(bredrInfo)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Transport != "BR/EDR" || len(r.Keys) != 1 {
		t.Errorf("transport=%q keys=%d", r.Transport, len(r.Keys))
	}
}

// A paired-then-cleared info file with metadata but no key sections is still a
// BlueZ file only if a key section exists; with none it is rejected.
func TestDecode_NoKeysRejected(t *testing.T) {
	const noKeys = `[General]
Name=Unpaired
SupportedTechnologies=LE;
[ConnectionParameters]
MinInterval=6
`
	if _, err := Decode(noKeys); err == nil {
		t.Error("expected rejection of a file with no key sections")
	}
}

func TestDecode_Errors(t *testing.T) {
	for name, in := range map[string]string{
		"empty":     "",
		"unrelated": "[wifi]\nssid=Foo\npsk=bar",
		"random":    "just text\nno sections",
	} {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(dualInfo)
	f.Add(leInfo)
	f.Add(bredrInfo)
	f.Add("[LinkKey]\nKey=")
	f.Add("")
	f.Fuzz(func(_ *testing.T, in string) {
		_, _ = Decode(in)
	})
}
