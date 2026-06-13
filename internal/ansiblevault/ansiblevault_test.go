package ansiblevault

import "testing"

// Header shapes verified against real ansible-core VaultLib output:
//
//	v1.1: $ANSIBLE_VAULT;1.1;AES256
//	v1.2: $ANSIBLE_VAULT;1.2;AES256;<vault-id>
const vault11 = `$ANSIBLE_VAULT;1.1;AES256
33646465656565623236346564356435616563656639613862613835663930383231353931313464
3930666461386162393463343031326635613639336131613664383738653263636533653063`

const vault12 = `$ANSIBLE_VAULT;1.2;AES256;prod
32393365616336626534356463373437666361393762303030303734646265663633343962353639
6464336265643731376337373764626161393432663036340a353837623466653937333834303237`

func TestDecode_V11(t *testing.T) {
	r, err := Decode(vault11)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != "1.1" || r.Cipher != "AES256" || r.VaultID != "" {
		t.Errorf("v=%q cipher=%q id=%q", r.Version, r.Cipher, r.VaultID)
	}
	if r.HashcatMode != 16900 || r.JohnTool != "ansible2john" {
		t.Errorf("mode=%d john=%q", r.HashcatMode, r.JohnTool)
	}
	if r.BodyBytes <= 0 {
		t.Errorf("body bytes = %d, want > 0", r.BodyBytes)
	}
}

// realVault and wantJohn are a ground-truth pair: realVault is the verbatim
// output of `ansible-vault encrypt` (ansible-core, AES256) over a two-line YAML
// file; wantJohn is the matching ansible2john / hashcat-16900 hash, derived from
// the documented envelope (single hex-decode → salt\nhmac\nciphertext).
const realVault = `$ANSIBLE_VAULT;1.1;AES256
61383330383961396466333235663037316432396136383435613633383937336434653963383062
3733623035396430663039373961323833303662623133330a336239303361333431376433356162
37653563363436333138303938333936353837363934643138376533333037313133613930303033
3232333161336637380a336235633665353036393332613262306631333464343934343838663831
64343730663533353233653536643931653436353864363961383331623934626333303734323231
6530376636393232373136323935383636656230326563636261`

const wantJohn = "$ansible$0*0*" +
	"a83089a9df325f071d29a6845a638973d4e9c80b73b059d0f0979a28306bb133*" +
	"3b903a3417d35ab7e5c646318098396587694d187e3307113a900032231a3f78*" +
	"3b5c6e506932a2b0f134d494488f81d470f53523e56d91e4658d69a831b94bc3074221e07f6922716295866eb02eccba"

func TestDecode_JohnHash(t *testing.T) {
	r, err := Decode(realVault)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.JohnHash != wantJohn {
		t.Errorf("JohnHash mismatch\n got: %q\nwant: %q", r.JohnHash, wantJohn)
	}
}

// A truncated / malformed body must not yield a hash — no confidently-wrong
// output. The short fixture bodies above do not hex-decode into three
// well-formed fields, so JohnHash stays empty.
func TestDecode_NoJohnHashOnMalformedBody(t *testing.T) {
	for name, in := range map[string]string{
		"truncated v1.1": vault11,
		"truncated v1.2": vault12,
		"header only":    "$ANSIBLE_VAULT;1.1;AES256",
	} {
		r, err := Decode(in)
		if err != nil {
			t.Fatalf("%s: Decode: %v", name, err)
		}
		if r.JohnHash != "" {
			t.Errorf("%s: JohnHash = %q, want empty", name, r.JohnHash)
		}
	}
}

func TestDecode_V12VaultID(t *testing.T) {
	r, err := Decode(vault12)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != "1.2" || r.VaultID != "prod" {
		t.Errorf("v=%q id=%q, want 1.2/prod", r.Version, r.VaultID)
	}
}

func TestDecode_Errors(t *testing.T) {
	for name, in := range map[string]string{
		"empty":      "",
		"not vault":  "secret: plaintext value\n",
		"bad header": "$ANSIBLE_VAULT;1.1\n",
	} {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(vault11)
	f.Add(vault12)
	f.Add(realVault)
	f.Add("$ANSIBLE_VAULT;")
	f.Add("")
	f.Fuzz(func(_ *testing.T, in string) {
		_, _ = Decode(in)
	})
}
