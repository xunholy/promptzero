package wificonfig

import "testing"

func find(t *testing.T, ns []Network, ssid string) Network {
	t.Helper()
	for _, n := range ns {
		if n.SSID == ssid {
			return n
		}
	}
	t.Fatalf("network %q not found in %+v", ssid, ns)
	return Network{}
}

const wpaSupplicant = `ctrl_interface=/run/wpa_supplicant
update_config=1

network={
	ssid="HomeNet"
	psk="s3cr3tpass"
	key_mgmt=WPA-PSK
}

network={
	ssid="CoffeeShop"
	key_mgmt=NONE
}

network={
	ssid="HiddenCorp"
	scan_ssid=1
	key_mgmt=WPA-EAP
	eap=PEAP
	identity="alice@corp.example"
	password="domainpass"
}

network={
	ssid="HexPskNet"
	psk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
}
`

func TestDecode_WpaSupplicant(t *testing.T) {
	r, err := Decode(wpaSupplicant)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Format != "wpa_supplicant" {
		t.Fatalf("format = %q", r.Format)
	}
	if len(r.Networks) != 4 {
		t.Fatalf("networks = %d, want 4", len(r.Networks))
	}
	home := find(t, r.Networks, "HomeNet")
	if home.PSK != "s3cr3tpass" || home.KeyMgmt != "WPA-PSK" || home.PSKType != "passphrase" {
		t.Errorf("HomeNet = %+v", home)
	}
	open := find(t, r.Networks, "CoffeeShop")
	if open.KeyMgmt != "OPEN" || open.PSK != "" || open.HasCredential() {
		t.Errorf("CoffeeShop = %+v, want open/no-cred", open)
	}
	corp := find(t, r.Networks, "HiddenCorp")
	if corp.KeyMgmt != "WPA-EAP" || corp.EAPMethod != "PEAP" || corp.Identity != "alice@corp.example" ||
		corp.EAPPassword != "domainpass" || !corp.Hidden {
		t.Errorf("HiddenCorp = %+v", corp)
	}
	hex := find(t, r.Networks, "HexPskNet")
	if hex.PSKType != "hex" || hex.KeyMgmt != "WPA-PSK" || len(hex.PSK) != 64 {
		t.Errorf("HexPskNet = %+v", hex)
	}
	// HomeNet + HiddenCorp + HexPskNet carry credentials; CoffeeShop does not.
	if r.CredentialCount != 3 {
		t.Errorf("credential count = %d, want 3", r.CredentialCount)
	}
}

const nmConnection = `[connection]
id=OfficeWiFi
type=wifi

[wifi]
mode=infrastructure
ssid=OfficeWiFi

[wifi-security]
key-mgmt=wpa-psk
psk=Office!Pass123
`

func TestDecode_NetworkManager(t *testing.T) {
	r, err := Decode(nmConnection)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Format != "NetworkManager" || len(r.Networks) != 1 {
		t.Fatalf("format=%q networks=%d", r.Format, len(r.Networks))
	}
	n := r.Networks[0]
	if n.SSID != "OfficeWiFi" || n.KeyMgmt != "WPA-PSK" || n.PSK != "Office!Pass123" {
		t.Errorf("network = %+v", n)
	}
	if r.CredentialCount != 1 {
		t.Errorf("credential count = %d, want 1", r.CredentialCount)
	}
}

const nmEnterprise = `[connection]
id=Corp
type=wifi
[wifi]
ssid=CorpNet
[wifi-security]
key-mgmt=wpa-eap
[802-1x]
eap=peap;
identity=bob
password=hunter2
`

func TestDecode_NetworkManagerEnterprise(t *testing.T) {
	r, err := Decode(nmEnterprise)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	n := r.Networks[0]
	if n.KeyMgmt != "WPA-EAP" || n.Identity != "bob" || n.EAPPassword != "hunter2" {
		t.Errorf("enterprise = %+v", n)
	}
}

const winXMLPlain = `<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>HomeAP</name>
  <SSIDConfig><SSID><name>HomeAP</name></SSID></SSIDConfig>
  <MSM><security>
    <authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption></authEncryption>
    <sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>WinPass!2024</keyMaterial></sharedKey>
  </security></MSM>
</WLANProfile>`

func TestDecode_WindowsXMLPlain(t *testing.T) {
	r, err := Decode(winXMLPlain)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Format != "windows-wlan-xml" {
		t.Fatalf("format = %q", r.Format)
	}
	n := r.Networks[0]
	if n.SSID != "HomeAP" || n.KeyMgmt != "WPA-PSK" || n.PSK != "WinPass!2024" || n.PSKEncrypted {
		t.Errorf("network = %+v", n)
	}
	if r.CredentialCount != 1 {
		t.Errorf("credential count = %d, want 1", r.CredentialCount)
	}
}

const winXMLProtected = `<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <SSIDConfig><SSID><name>LockedAP</name></SSID></SSIDConfig>
  <MSM><security>
    <authEncryption><authentication>WPA2PSK</authentication></authEncryption>
    <sharedKey><keyType>passPhrase</keyType><protected>true</protected><keyMaterial>0100000DEADBEEF</keyMaterial></sharedKey>
  </security></MSM>
</WLANProfile>`

// A DPAPI-protected key must be flagged encrypted, not surfaced as a plaintext credential.
func TestDecode_WindowsXMLProtected(t *testing.T) {
	r, err := Decode(winXMLProtected)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	n := r.Networks[0]
	if !n.PSKEncrypted || n.HasCredential() {
		t.Errorf("protected key should be flagged encrypted / no-cred: %+v", n)
	}
	if r.CredentialCount != 0 {
		t.Errorf("credential count = %d, want 0 (encrypted)", r.CredentialCount)
	}
}

func TestDecode_Errors(t *testing.T) {
	for name, in := range map[string]string{
		"empty":     "",
		"unrelated": "just some random text\nwith lines",
		"bad xml":   "<WLANProfile><SSIDConfig",
	} {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(wpaSupplicant)
	f.Add(nmConnection)
	f.Add(winXMLPlain)
	f.Add("network={")
	f.Add("")
	f.Fuzz(func(_ *testing.T, in string) {
		_, _ = Decode(in)
	})
}
