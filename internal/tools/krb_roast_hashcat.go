// krb_roast_hashcat.go — host-side Kerberoast / AS-REP-roast crack-line builder
// Spec, delegating to internal/krbroast.
//
// Wrap-vs-native: native — it reuses the in-tree internal/kerberos AS-REP /
// TGS-REP + Ticket decoder and assembles the hashcat 18200 / 13100 crack line
// (an enc-part length split + a format string). The capture->crackable-hash
// step for Kerberos, the sibling of netntlm_hashcat for NTLM. Offline.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/krbroast"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(krbRoastHashcatSpec)
}

var krbRoastHashcatSpec = Spec{
	Name: "krb_roast_hashcat",
	Description: "Assemble the **hashcat crack line** for the two dominant offline Kerberos credential " +
		"attacks, from a captured KDC response — the capture→crackable-hash step for Kerberos, the sibling " +
		"of netntlm_hashcat for NTLM. kerberos_decode surfaces the encrypted parts; this emits the " +
		"ready-to-crack line:\n\n" +
		"- **AS-REP roast** (hashcat `-m 18200`): paste an **AS-REP** (for a user with Kerberos pre-auth " +
		"disabled — its enc-part is encrypted with the user's password-derived key) → " +
		"`$krb5asrep$23$user@REALM:checksum$edata`.\n" +
		"- **Kerberoast** (hashcat `-m 13100`): paste a **TGS-REP** (its service ticket's enc-part is " +
		"encrypted with the service account's key) → `$krb5tgs$23$*user$REALM$spn*$checksum$edata` (the SPN " +
		"is taken from the service ticket's sname).\n\n" +
		"Both **RC4 (etype 23)** and **AES (etype 17/18)** tickets are handled, matching impacket's " +
		"GetUserSPNs / GetNPUsers exactly: RC4 splits checksum(16)‖edata (Kerberoast 13100 / AS-REP " +
		"18200); AES splits edata‖checksum(12) — the checksum is the LAST 12 bytes — with the SPN " +
		"`*`-wrapped alone and ':'→'~' (AES Kerberoast 19600 / 19700). AES AS-REP roast has no standard " +
		"hashcat mode and is flagged for John the Ripper.\n\n" +
		"Provide **message** (the AS-REP / TGS-REP as hex — the same input kerberos_decode takes; the message " +
		"type selects the attack). Output is the crack line + the hashcat mode + the principal / SPN / realm.\n\n" +
		"Pure offline transform — reads operator-supplied hex, transmits nothing, so it is Low risk. A " +
		"non-AS-REP/TGS-REP input, or any other etype, errors instead of emitting a wrong line. Verified " +
		"in-tree against spec-conformant AS-REP + TGS-REP vectors (RC4 + AES) reproducing the canonical " +
		"hashcat / impacket lines byte-for-byte. Wrap-vs-native: native — reuses the internal/kerberos decoder.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"message":{"type":"string","description":"The AS-REP (for AS-REP roast → 18200) or TGS-REP (for Kerberoast → 13100) as hex. Separators / '0x' tolerated (same as kerberos_decode)."}
		},
		"required":["message"]
	}`),
	Required:  []string{"message"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   krbRoastHashcatHandler,
}

func krbRoastHashcatHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	msg := strings.TrimSpace(str(p, "message"))
	if msg == "" {
		return "", fmt.Errorf("krb_roast_hashcat: 'message' is required")
	}
	res, err := krbroast.RoastLine(msg)
	if err != nil {
		return "", fmt.Errorf("krb_roast_hashcat: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
