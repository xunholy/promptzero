package vpnconfig

import "testing"

const wireguardConf = `[Interface]
PrivateKey = aGVsbG93b3JsZGtleWJhc2U2NHBsYWNlaG9sZGVyMTIzND0=
Address = 10.7.0.2/24
DNS = 1.1.1.1
ListenPort = 51820

[Peer]
PublicKey = cGVlcnB1YmxpY2tleWJhc2U2NHBsYWNlaG9sZGVyMTIzND0=
PresharedKey = cHJlc2hhcmVka2V5YmFzZTY0cGxhY2Vob2xkZXIxMjM0PQ==
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
`

func TestDecode_WireGuard(t *testing.T) {
	r, err := Decode(wireguardConf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Format != "wireguard" {
		t.Fatalf("format = %q", r.Format)
	}
	if r.PrivateKey != "aGVsbG93b3JsZGtleWJhc2U2NHBsYWNlaG9sZGVyMTIzND0=" || !r.HasCredential {
		t.Errorf("private key/cred = %q/%v", r.PrivateKey, r.HasCredential)
	}
	if r.Address != "10.7.0.2/24" || r.ListenPort != "51820" {
		t.Errorf("address=%q port=%q", r.Address, r.ListenPort)
	}
	if len(r.Peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(r.Peers))
	}
	p := r.Peers[0]
	if p.Endpoint != "vpn.example.com:51820" || p.PresharedKey == "" || p.AllowedIPs != "0.0.0.0/0" {
		t.Errorf("peer = %+v", p)
	}
}

const openvpnCert = `client
dev tun
proto udp
remote vpn.corp.example.com 1194
remote backup.corp.example.com 1194
cipher AES-256-GCM
<ca>
-----BEGIN CERTIFICATE-----
MIIB...
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIIB...
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIEvQ...
-----END PRIVATE KEY-----
</key>
`

func TestDecode_OpenVPNCert(t *testing.T) {
	r, err := Decode(openvpnCert)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Format != "openvpn" {
		t.Fatalf("format = %q", r.Format)
	}
	if len(r.Remotes) != 2 || r.Remotes[0] != "vpn.corp.example.com 1194" {
		t.Errorf("remotes = %v", r.Remotes)
	}
	if r.Proto != "udp" {
		t.Errorf("proto = %q", r.Proto)
	}
	if !r.EmbeddedPrivateKey || !r.CACertPresent || !r.ClientCertPresent {
		t.Errorf("flags: key=%v ca=%v cert=%v", r.EmbeddedPrivateKey, r.CACertPresent, r.ClientCertPresent)
	}
	if r.AuthMethod != "certificate" || !r.HasCredential {
		t.Errorf("auth=%q cred=%v", r.AuthMethod, r.HasCredential)
	}
}

const openvpnUserPass = `client
dev tun
proto tcp
remote vpn.example.net 443
auth-user-pass
<auth-user-pass>
alice
S3cretVPNpass
</auth-user-pass>
`

func TestDecode_OpenVPNUserPass(t *testing.T) {
	r, err := Decode(openvpnUserPass)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Username != "alice" || r.Password != "S3cretVPNpass" {
		t.Errorf("creds = %q / %q", r.Username, r.Password)
	}
	if r.AuthMethod != "user-pass" || !r.HasCredential {
		t.Errorf("auth=%q cred=%v", r.AuthMethod, r.HasCredential)
	}
}

func TestDecode_Errors(t *testing.T) {
	for name, in := range map[string]string{
		"empty":     "",
		"unrelated": "just some text\nwith no vpn markers",
		"wifi":      "[connection]\ntype=wifi",
	} {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(wireguardConf)
	f.Add(openvpnCert)
	f.Add(openvpnUserPass)
	f.Add("[Interface]\nPrivateKey=")
	f.Add("remote x 1\n<key>")
	f.Add("")
	f.Fuzz(func(_ *testing.T, in string) {
		_, _ = Decode(in)
	})
}
