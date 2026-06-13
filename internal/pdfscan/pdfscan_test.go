package pdfscan

import (
	"strings"
	"testing"
)

const benignPDF = `%PDF-1.7
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
trailer
<< /Root 1 0 R >>
%%EOF
`

// auto-runs JavaScript on open via /OpenAction.
const jsPDF = `%PDF-1.7
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert\(1\)) >> >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R >>
endobj
trailer
<< /Root 1 0 R >>
%%EOF
`

// same, but the /JavaScript name is hidden with a PDF hex-escape (#61 == 'a').
const obfPDF = `%PDF-1.7
1 0 obj
<< /Type /Catalog /OpenAction << /S /J#61vaScript /JS (x) >> >>
endobj
trailer
<< /Root 1 0 R >>
%%EOF
`

// runs an external program via /Launch.
const launchPDF = `%PDF-1.7
1 0 obj
<< /Type /Catalog /OpenAction << /S /Launch /F (cmd.exe) >> >>
endobj
trailer
<< /Root 1 0 R >>
%%EOF
`

func kw(r *Result, name string) (Keyword, bool) {
	for _, k := range r.Keywords {
		if k.Name == name {
			return k, true
		}
	}
	return Keyword{}, false
}

func hasReason(r *Result, name string) bool {
	for _, x := range r.DangerReasons {
		if x == name {
			return true
		}
	}
	return false
}

func TestScan_Benign(t *testing.T) {
	r, err := Scan([]byte(benignPDF))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if r.Version != "1.7" {
		t.Errorf("version = %q, want 1.7", r.Version)
	}
	if r.Dangerous || r.Obfuscation {
		t.Errorf("benign flagged: dangerous=%v obf=%v reasons=%v", r.Dangerous, r.Obfuscation, r.DangerReasons)
	}
	if _, ok := kw(r, "/JavaScript"); ok {
		t.Errorf("benign has /JavaScript")
	}
}

func TestScan_AutoRunJS(t *testing.T) {
	r, err := Scan([]byte(jsPDF))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !r.Dangerous {
		t.Fatal("expected dangerous")
	}
	for _, name := range []string{"/JavaScript", "/JS", "/OpenAction"} {
		k, ok := kw(r, name)
		if !ok || k.Count < 1 {
			t.Errorf("%s not counted: %+v", name, k)
		}
		if !hasReason(r, name) && (name == "/JavaScript" || name == "/JS" || name == "/OpenAction") {
			t.Errorf("danger_reasons missing %s", name)
		}
	}
	if r.Obfuscation {
		t.Errorf("plain JS PDF should not be flagged obfuscated")
	}
}

func TestScan_HexEscapeDeobfuscation(t *testing.T) {
	r, err := Scan([]byte(obfPDF))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	k, ok := kw(r, "/JavaScript")
	if !ok || k.Count != 1 || !k.Obfuscated {
		t.Errorf("obfuscated /JavaScript not de-obfuscated: %+v (ok=%v)", k, ok)
	}
	if !r.Obfuscation || !r.Dangerous {
		t.Errorf("expected obfuscation+dangerous, got obf=%v danger=%v", r.Obfuscation, r.Dangerous)
	}
	if !strings.Contains(r.Note, "obfuscation") && !strings.Contains(r.Note, "SUSPICIOUS") {
		t.Errorf("note: %q", r.Note)
	}
}

func TestScan_Launch(t *testing.T) {
	r, err := Scan([]byte(launchPDF))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !r.Dangerous || !hasReason(r, "/Launch") {
		t.Errorf("Launch not flagged: %+v", r)
	}
}

func TestScan_Errors(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":  {},
		"no pdf": []byte("just some text, not a pdf at all"),
	} {
		if _, err := Scan(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func FuzzScan(f *testing.F) {
	f.Add([]byte(benignPDF))
	f.Add([]byte(jsPDF))
	f.Add([]byte(obfPDF))
	f.Add([]byte("%PDF-1.4\n/J#"))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, in []byte) {
		_, _ = Scan(in)
	})
}
