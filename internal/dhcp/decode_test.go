package dhcp

import (
	"encoding/binary"
	"strings"
	"testing"
)

// TestDecode_DHCPDiscover pins a hand-crafted DHCPDISCOVER:
// op=BOOTREQUEST + Ethernet + zero IPs + xid + transaction
// fields + magic cookie + option 53 (DISCOVER) + option 55
// (Parameter Request List) + option 61 (Client ID) + end.
func TestDecode_DHCPDiscover(t *testing.T) {
	pkt := buildDiscoverPacket(t, 0xDEADBEEF, []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.OpName != "BOOTREQUEST" {
		t.Errorf("OpName = %q", got.OpName)
	}
	if got.HTypeName != "Ethernet" {
		t.Errorf("HTypeName = %q", got.HTypeName)
	}
	if got.HLen != 6 {
		t.Errorf("HLen = %d", got.HLen)
	}
	if got.XID != 0xDEADBEEF {
		t.Errorf("XID = 0x%08X", got.XID)
	}
	if got.ClientHwMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("ClientHwMAC = %q", got.ClientHwMAC)
	}
	if got.MagicCookie != "0x63825363" {
		t.Errorf("MagicCookie = %q", got.MagicCookie)
	}
	if got.MessageType != "DISCOVER" {
		t.Errorf("MessageType = %q", got.MessageType)
	}
	// Verify Parameter Request List is named-decoded
	var prl *Option
	for _, opt := range got.Options {
		if opt.Code == 55 {
			prl = opt
			break
		}
	}
	if prl == nil {
		t.Fatal("Parameter Request List option missing")
	}
	if len(prl.ParameterList) == 0 {
		t.Error("ParameterList empty")
	}
	if !containsStr(prl.ParameterList, "Subnet Mask") {
		t.Errorf("ParameterList missing 'Subnet Mask': %v", prl.ParameterList)
	}
}

// TestDecode_DHCPACK_WithLease pins a DHCPACK response with
// option 51 (Lease Time), 1 (Subnet), 3 (Router), 6 (DNS).
func TestDecode_DHCPACK_WithLease(t *testing.T) {
	pkt := buildAckPacket(t, 0x12345678, []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		[]byte{192, 168, 1, 100}, []byte{192, 168, 1, 1},
		[]byte{255, 255, 255, 0},
		[][]byte{{8, 8, 8, 8}, {1, 1, 1, 1}},
		86400)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.OpName != "BOOTREPLY" {
		t.Errorf("OpName = %q", got.OpName)
	}
	if got.YiAddr != "192.168.1.100" {
		t.Errorf("YiAddr = %q", got.YiAddr)
	}
	if got.MessageType != "ACK" {
		t.Errorf("MessageType = %q", got.MessageType)
	}
	var subnet, lease, router, dns *Option
	for _, opt := range got.Options {
		switch opt.Code {
		case 1:
			subnet = opt
		case 3:
			router = opt
		case 6:
			dns = opt
		case 51:
			lease = opt
		}
	}
	if subnet == nil || subnet.IPv4 != "255.255.255.0" {
		t.Errorf("Subnet = %v", subnet)
	}
	if router == nil || len(router.IPv4List) != 1 || router.IPv4List[0] != "192.168.1.1" {
		t.Errorf("Router = %v", router)
	}
	if dns == nil || len(dns.IPv4List) != 2 {
		t.Fatalf("DNS = %v", dns)
	}
	if dns.IPv4List[0] != "8.8.8.8" {
		t.Errorf("DNS[0] = %q", dns.IPv4List[0])
	}
	if lease == nil || lease.Uint32Value != 86400 {
		t.Errorf("Lease = %v", lease)
	}
}

// TestDecode_OptionFQDN pins an option-81 Client FQDN decode.
func TestDecode_OptionFQDN(t *testing.T) {
	body := []byte{0x04, 0xFF, 0xFF} // flags=4, A-result=255, AAAA-result=255
	body = append(body, []byte("test.example.com")...)
	pkt := buildPacketWithOptions(t, 1, []byte{0x00, 0x00, 0x00, 0x01}, [][]byte{
		{53, 1, 1}, // DISCOVER
		append([]byte{81, byte(len(body))}, body...),
	})
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var fqdn *Option
	for _, opt := range got.Options {
		if opt.Code == 81 {
			fqdn = opt
			break
		}
	}
	if fqdn == nil || fqdn.FQDN == nil {
		t.Fatal("FQDN option missing")
	}
	if fqdn.FQDN.Flags != 0x04 {
		t.Errorf("FQDN.Flags = %d", fqdn.FQDN.Flags)
	}
	if fqdn.FQDN.FQDN != "test.example.com" {
		t.Errorf("FQDN.FQDN = %q", fqdn.FQDN.FQDN)
	}
}

// TestDecode_OptionRelayAgent pins an option-82 sub-option
// walk.
func TestDecode_OptionRelayAgent(t *testing.T) {
	// 1 = Circuit ID = "eth0/0/1"
	// 2 = Remote ID = "00:11:22:33:44:55"
	circuitID := []byte("eth0/0/1")
	remoteID := []byte("00:11:22:33:44:55")
	suboptions := append([]byte{1, byte(len(circuitID))}, circuitID...)
	suboptions = append(suboptions, append([]byte{2, byte(len(remoteID))}, remoteID...)...)
	pkt := buildPacketWithOptions(t, 1, []byte{0x00, 0x00, 0x00, 0x01}, [][]byte{
		{53, 1, 3}, // REQUEST
		append([]byte{82, byte(len(suboptions))}, suboptions...),
	})
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var ra *Option
	for _, opt := range got.Options {
		if opt.Code == 82 {
			ra = opt
			break
		}
	}
	if ra == nil {
		t.Fatal("Option 82 missing")
	}
	if len(ra.RelayAgent) != 2 {
		t.Fatalf("RelayAgent sub-option count = %d", len(ra.RelayAgent))
	}
	if ra.RelayAgent[0].Name != "Agent Circuit ID" {
		t.Errorf("Sub[0].Name = %q", ra.RelayAgent[0].Name)
	}
	if ra.RelayAgent[1].Name != "Agent Remote ID" {
		t.Errorf("Sub[1].Name = %q", ra.RelayAgent[1].Name)
	}
}

// TestDecode_ClasslessRoutes pins option 121 decode for a
// route to 10.0.0.0/8 via 192.168.1.1.
func TestDecode_ClasslessRoutes(t *testing.T) {
	// Route entries: prefix=8 + 1 dest byte (10) + 4 gw bytes
	// (192, 168, 1, 1)
	routeData := []byte{8, 10, 192, 168, 1, 1}
	pkt := buildPacketWithOptions(t, 1, []byte{0x00, 0x00, 0x00, 0x01}, [][]byte{
		{53, 1, 5}, // ACK
		append([]byte{121, byte(len(routeData))}, routeData...),
	})
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var routes *Option
	for _, opt := range got.Options {
		if opt.Code == 121 {
			routes = opt
			break
		}
	}
	if routes == nil {
		t.Fatal("Option 121 missing")
	}
	if len(routes.ClasslessRoutes) != 1 {
		t.Fatalf("Routes count = %d", len(routes.ClasslessRoutes))
	}
	r := routes.ClasslessRoutes[0]
	if r.PrefixLen != 8 {
		t.Errorf("PrefixLen = %d", r.PrefixLen)
	}
	if r.Destination != "10.0.0.0" {
		t.Errorf("Destination = %q", r.Destination)
	}
	if r.Gateway != "192.168.1.1" {
		t.Errorf("Gateway = %q", r.Gateway)
	}
}

// TestDecode_BroadcastFlag pins the broadcast bit in flags.
func TestDecode_BroadcastFlag(t *testing.T) {
	pkt := buildDiscoverPacket(t, 0xDEADBEEF, []byte{0, 0, 0, 0, 0, 0})
	binary.BigEndian.PutUint16(pkt[10:12], 0x8000)
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.Broadcast {
		t.Error("Broadcast = false; want true")
	}
}

// TestDecode_BadMagicCookie rejects packets with the wrong
// cookie (= vanilla BOOTP rather than DHCP).
func TestDecode_BadMagicCookie(t *testing.T) {
	pkt := buildDiscoverPacket(t, 0x12345678, []byte{0, 0, 0, 0, 0, 0})
	binary.BigEndian.PutUint32(pkt[236:240], 0xDEADBEEF)
	if _, err := DecodeBytes(pkt); err == nil {
		t.Error("bad magic cookie: want error")
	}
}

// TestDecode_TooShort rejects packets < 240 bytes.
func TestDecode_TooShort(t *testing.T) {
	if _, err := Decode("00 01 02 03"); err == nil {
		t.Error("4-byte input: want error")
	}
}

// TestDecode_BadHex rejects garbage.
func TestDecode_BadHex(t *testing.T) {
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
	if _, err := Decode(""); err == nil {
		t.Error("empty: want error")
	}
}

// TestMessageTypeTable spot-checks.
func TestMessageTypeTable(t *testing.T) {
	cases := map[int]string{
		1: "DISCOVER",
		2: "OFFER",
		3: "REQUEST",
		4: "DECLINE",
		5: "ACK",
		6: "NAK",
		7: "RELEASE",
		8: "INFORM",
	}
	for v, want := range cases {
		if got := messageTypeName(v); got != want {
			t.Errorf("messageTypeName(%d) = %q; want %q", v, got, want)
		}
	}
}

// TestOptionNameTable spot-checks.
func TestOptionNameTable(t *testing.T) {
	cases := map[int]string{
		1:   "Subnet Mask",
		3:   "Router",
		6:   "DNS Server",
		15:  "Domain Name",
		51:  "IP Address Lease Time",
		53:  "DHCP Message Type",
		54:  "DHCP Server Identifier",
		55:  "Parameter Request List",
		61:  "Client Identifier",
		82:  "Relay Agent Information",
		119: "Domain Search",
		121: "Classless Static Route",
		255: "End",
	}
	for v, want := range cases {
		if got := optionName(v); got != want {
			t.Errorf("optionName(%d) = %q; want %q", v, got, want)
		}
	}
}

// --- test helpers --------------------------------------------------

func buildBOOTPHeader(op byte, xid uint32, mac []byte) []byte {
	h := make([]byte, 236)
	h[0] = op
	h[1] = 0x01 // htype = Ethernet
	h[2] = 0x06 // hlen
	binary.BigEndian.PutUint32(h[4:8], xid)
	copy(h[28:34], mac)
	return h
}

func buildDiscoverPacket(t *testing.T, xid uint32, mac []byte) []byte {
	t.Helper()
	pkt := buildPacketWithOptions(t, 1, encodeUint32(xid), [][]byte{
		{53, 1, 1},               // DISCOVER
		{55, 5, 1, 3, 6, 15, 51}, // Parameter Request List
		{61, 7, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, // Client ID
	})
	// Write the MAC into chaddr (bytes 28..33 of the BOOTP
	// header that's the first 236 bytes of the packet).
	copy(pkt[28:34], mac)
	return pkt
}

func buildAckPacket(t *testing.T, xid uint32, mac, yiAddr, server, subnet []byte, dnsServers [][]byte, leaseSec uint32) []byte {
	t.Helper()
	pkt := buildBOOTPHeader(2, xid, mac)
	copy(pkt[16:20], yiAddr) // yiaddr
	copy(pkt[20:24], server) // siaddr
	cookie := make([]byte, 4)
	binary.BigEndian.PutUint32(cookie, 0x63825363)
	pkt = append(pkt, cookie...)

	// Options: 53 (ACK), 1 (subnet), 3 (router=server), 6 (DNS list), 51 (lease)
	pkt = append(pkt, 53, 1, 5)
	pkt = append(pkt, 1, 4)
	pkt = append(pkt, subnet...)
	pkt = append(pkt, 3, 4)
	pkt = append(pkt, server...)
	pkt = append(pkt, 6, byte(len(dnsServers)*4))
	for _, ip := range dnsServers {
		pkt = append(pkt, ip...)
	}
	leaseBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(leaseBytes, leaseSec)
	pkt = append(pkt, 51, 4)
	pkt = append(pkt, leaseBytes...)
	pkt = append(pkt, 255) // End
	return pkt
}

func buildPacketWithOptions(t *testing.T, op byte, xidBytes []byte, options [][]byte) []byte {
	t.Helper()
	pkt := make([]byte, 236)
	pkt[0] = op
	pkt[1] = 0x01
	pkt[2] = 0x06
	copy(pkt[4:8], xidBytes)
	cookie := make([]byte, 4)
	binary.BigEndian.PutUint32(cookie, 0x63825363)
	pkt = append(pkt, cookie...)
	for _, opt := range options {
		pkt = append(pkt, opt...)
	}
	pkt = append(pkt, 255)
	return pkt
}

func encodeUint32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func containsStr(haystack []string, needle string) bool {
	for _, s := range haystack {
		if strings.EqualFold(s, needle) {
			return true
		}
	}
	return false
}
