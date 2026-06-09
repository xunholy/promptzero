package roca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
)

// vulnerableModuli are the ten fingerprint-positive moduli from
// crocs-muni/roca tests/test_fingerprint.py (test_fake_mods): each is asserted
// vulnerable by the moduli-fingerprint method. They double as a transcription
// check — a single wrong digit shifts the residues mod the 38 primes and the
// fingerprint almost certainly stops matching, so all ten passing confirms
// both the algorithm port and these constants.
var vulnerableModuli = []string{
	"72414128973967872688332736535017614208620368242015797102796086827882754006260204061799547004983731426777596445658889886861027045033760014948048067467947960318205453778973975867532910489227970143091184725760290172935872752222320334100097730483600892686353719855397381316384244147860260153198611313067061116317",
	"138345973265163614694352477004469191286459111070564516299381495188624946671065451924677704628892476011773201612117597303315530745738015579159106259811204610647347662150159814774894784524366138220226431598991937057442020694466365850170057813627445465881816985939192840583168136876337135351417253708364245923133",
	"60828061238058485055546209519792949600733446820687109700021551748017165461584398468231416589035982737511901116540885252089750919566836183252857475484338913841291095222387779067564971983760619814471104385614285949705697261702933899278537712383849527252611987939947273446907728942539157463443880598175266703887",
	"89537174583470428126368559122733093792771267470145172261204043737374783295746735770977275377863486022234354929860172558745137290320682223277990399066906105916137221611218740752167456538787695936927885201842306174187254104613077236292789788064415254034851612157179926431228950237250716554645306298514263908811",
	"106012262050781200106909327696665817682864459575156325008493049499578896429709338134583432679663875229243561266610327817994340312544432988100581205278527652776797129380732775139010348828146830433114148695545628251479471386655045041620711043660854155633665634387716779804052874716264079804365681200926368878541",
	"98047438997515280074792701497622826536971900999197902469801657195397532486098993597664864573258672004307512856021908739030566926963054863998516343042890871462635847748128662678669505745602483507470396856696130729682439145004123654578085621747843892166517045343501758093052905936670793527374604000360320123643",
	"48107859163997579694864893504886560528514286462252528518753580114887818750322128218646068205130016527298578884960923054955072510745551784643455001265439464144751949280776912819502350769576504234639747590328838926697492194274517633949025303073843002256820311079628923909309353364288514091223779706534988233353",
	"95193465162148191217844814565725476305218769551232988131351154011966624770961320486395571928859840281251870272532908194236488486001519948267693888769624645565515338392649711205572847326959985300653388437498035890136677149175252923464027081780534454300684502200232492689914254307896522690747556123142494605401",
	"168489441676498254188251084620317730514271361861339944910962927459542807975808481932360687459768443345754506784027235857753721317508760585508375364503886428020727192193297507131796130690248490645731180656182669717283026722056291513041731668953221561576833358510127447655469989100576330621949276177058083620677",
	"127791896675045040395064468573109425010219774613093240038326469106056928318395608480165676859635771156871330139281596703754063207095456065784747740162970184880536590144647003492364759169502217854388165521994268206346785403332622195574508223431200064645819724980706217912475871209058082764033948277691466089251",
}

func TestHasFingerprint_Vulnerable(t *testing.T) {
	for i, s := range vulnerableModuli {
		n, ok := new(big.Int).SetString(s, 10)
		if !ok {
			t.Fatalf("vector %d: could not parse modulus", i)
		}
		if !HasFingerprint(n) {
			t.Errorf("vector %d (%d-bit): want fingerprint, got none", i, n.BitLen())
		}
	}
}

// TestDetect_VulnerableDecimal exercises the full Detect path on a decimal
// modulus and checks the surfaced metadata.
func TestDetect_VulnerableDecimal(t *testing.T) {
	res, err := Detect(vulnerableModuli[0])
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("want vulnerable, got clean")
	}
	if res.Source != "modulus" {
		t.Errorf("source = %q, want modulus", res.Source)
	}
	if res.KeyBits < 1000 || res.KeyBits > 1024 {
		t.Errorf("key bits = %d, want ~1024", res.KeyBits)
	}
	if res.ModulusHex == "" || res.Note == "" {
		t.Errorf("expected hex + note to be populated, got %q / %q", res.ModulusHex, res.Note)
	}
}

// TestDetect_HexMatchesDecimal confirms the same modulus parses identically as
// hex (0x-prefixed) and decimal.
func TestDetect_HexMatchesDecimal(t *testing.T) {
	n, _ := new(big.Int).SetString(vulnerableModuli[1], 10)
	res, err := Detect("0x" + n.Text(16))
	if err != nil {
		t.Fatalf("Detect hex: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("hex form: want vulnerable, got clean")
	}
}

// TestHasFingerprint_SoundKeys generates real RSA keys with Go's crypto/rsa
// (a non-Infineon library) and asserts none carry the fingerprint — the
// false-positive guard.
func TestHasFingerprint_SoundKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping RSA keygen in -short")
	}
	for i := 0; i < 8; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("keygen %d: %v", i, err)
		}
		if HasFingerprint(key.N) {
			t.Errorf("sound 2048-bit key %d falsely fingerprinted", i)
		}
	}
}

// TestDetect_PEMPublicKey round-trips a sound RSA key through PKIX PEM and the
// detector, asserting clean and correct source attribution.
func TestDetect_PEMPublicKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping RSA keygen in -short")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	res, err := Detect(string(pemBytes))
	if err != nil {
		t.Fatalf("Detect PEM: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("sound key flagged vulnerable")
	}
	if res.Source != "pem-pkix" {
		t.Errorf("source = %q, want pem-pkix", res.Source)
	}
}

// TestDetect_PKCS1PublicKey covers the "RSA PUBLIC KEY" PEM block path.
func TestDetect_PKCS1PublicKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping RSA keygen in -short")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: der})
	res, err := Detect(string(pemBytes))
	if err != nil {
		t.Fatalf("Detect PKCS1: %v", err)
	}
	if res.Source != "pem-pkcs1" {
		t.Errorf("source = %q, want pem-pkcs1", res.Source)
	}
}

// TestDetect_SSHRSA builds a real ssh-rsa wire blob from a sound key and checks
// the native parser extracts the right modulus.
func TestDetect_SSHRSA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping RSA keygen in -short")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	line := "ssh-rsa " + sshRSALine(t, &key.PublicKey) + " user@host"
	res, err := Detect(line)
	if err != nil {
		t.Fatalf("Detect ssh-rsa: %v", err)
	}
	if res.Source != "ssh-rsa" {
		t.Errorf("source = %q, want ssh-rsa", res.Source)
	}
	if res.ModulusHex != key.N.Text(16) {
		t.Errorf("parsed modulus mismatch")
	}
}

func TestDetect_Errors(t *testing.T) {
	cases := []string{"", "   ", "not-a-key", "ssh-rsa", "-----BEGIN GARBAGE-----\nzz\n-----END GARBAGE-----"}
	for _, c := range cases {
		if _, err := Detect(c); err == nil {
			t.Errorf("Detect(%q): want error, got nil", c)
		}
	}
}

func TestHasFingerprint_NonPositive(t *testing.T) {
	for _, n := range []*big.Int{nil, big.NewInt(0), big.NewInt(-7)} {
		if HasFingerprint(n) {
			t.Errorf("HasFingerprint(%v) = true, want false", n)
		}
	}
}

// sshRSALine encodes an RSA public key into the RFC 4253 ssh-rsa base64 blob
// using the same length-prefixed wire format the detector parses.
func sshRSALine(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	e := big.NewInt(int64(pub.E)).Bytes()
	n := pub.N.Bytes()
	// mpint encoding: prepend a zero byte if the high bit is set so the value
	// is read as positive, matching OpenSSH.
	if len(n) > 0 && n[0]&0x80 != 0 {
		n = append([]byte{0}, n...)
	}
	if len(e) > 0 && e[0]&0x80 != 0 {
		e = append([]byte{0}, e...)
	}
	var buf []byte
	put := func(b []byte) {
		var l [4]byte
		l[0] = byte(len(b) >> 24)
		l[1] = byte(len(b) >> 16)
		l[2] = byte(len(b) >> 8)
		l[3] = byte(len(b))
		buf = append(buf, l[:]...)
		buf = append(buf, b...)
	}
	put([]byte("ssh-rsa"))
	put(e)
	put(n)
	return base64.StdEncoding.EncodeToString(buf)
}
