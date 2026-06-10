package pdftriage

import (
	"encoding/base64"
	"testing"
)

// Real encrypted PDFs generated with pikepdf/qpdf (owner "opass", user "upass"):
//
//	pdfRC4    — V4/R4, crypt filter /V2   (RC4-128)   → hashcat 10500
//	pdfAES128 — V4/R4, crypt filter /AESV2 (AES-128)  → hashcat 10600
//	pdfAES256 — V5/R6, crypt filter /AESV3 (AES-256)  → hashcat 10700
const pdfRC4 = "JVBERi0xLjUKJb/3ov4KMSAwIG9iago8PCAvUGFnZXMgMiAwIFIgL1R5cGUgL0NhdGFsb2cg" +
	"Pj4KZW5kb2JqCjIgMCBvYmoKPDwgL0NvdW50IDEgL0tpZHMgWyAzIDAgUiBdIC9UeXBlIC9Q" +
	"YWdlcyA+PgplbmRvYmoKMyAwIG9iago8PCAvQ29udGVudHMgNCAwIFIgL01lZGlhQm94IFsg" +
	"MCAwIDYxMiA3OTIgXSAvUGFyZW50IDIgMCBSIC9SZXNvdXJjZXMgPDwgPj4gL1R5cGUgL1Bh" +
	"Z2UgPj4KZW5kb2JqCjQgMCBvYmoKPDwgL0xlbmd0aCAwIC9GaWx0ZXIgL0ZsYXRlRGVjb2Rl" +
	"ID4+CnN0cmVhbQoKZW5kc3RyZWFtCmVuZG9iago1IDAgb2JqCjw8IC9DRiA8PCAvU3RkQ0Yg" +
	"PDwgL0F1dGhFdmVudCAvRG9jT3BlbiAvQ0ZNIC9WMiAvTGVuZ3RoIDE2ID4+ID4+IC9FbmNy" +
	"eXB0TWV0YWRhdGEgZmFsc2UgL0ZpbHRlciAvU3RhbmRhcmQgL0xlbmd0aCAxMjggL08gPGY4" +
	"NTBjYmI1MDVjYWM3OGY5M2U4MzFiOWY2YWFmOWJmNTY2ZWVjYjRlOWQwOWMyODM0NDA2OTU0" +
	"MjQ4MDUwMjM+IC9PRSA8PiAvUCAtMTAyOCAvUiA0IC9TdG1GIC9TdGRDRiAvU3RyRiAvU3Rk" +
	"Q0YgL1UgPGIxMThjNjNhZTgyZTJlOTljYjhlMTRhNzMzMzlhZGMyMDAyMTQ0Njk5MGI5ZTQx" +
	"MTQwNzFhNGQ5MTA0OTg0YzE+IC9VRSA8PiAvViA0ID4+CmVuZG9iagp4cmVmCjAgNgowMDAw" +
	"MDAwMDAwIDY1NTM1IGYgCjAwMDAwMDAwMTUgMDAwMDAgbiAKMDAwMDAwMDA2NCAwMDAwMCBu" +
	"IAowMDAwMDAwMTIzIDAwMDAwIG4gCjAwMDAwMDAyMjkgMDAwMDAgbiAKMDAwMDAwMDI5OSAw" +
	"MDAwMCBuIAp0cmFpbGVyIDw8IC9Sb290IDEgMCBSIC9TaXplIDYgL0lEIFs8ZWI0N2EzNzhm" +
	"ZjBkNDVhNzRmMzk2OGI4MTczZDM4YjU+PGViNDdhMzc4ZmYwZDQ1YTc0ZjM5NjhiODE3M2Qz" +
	"OGI1Pl0gL0VuY3J5cHQgNSAwIFIgPj4Kc3RhcnR4cmVmCjYzNQolJUVPRgo="

const pdfAES128 = "JVBERi0xLjYKJb/3ov4KMSAwIG9iago8PCAvUGFnZXMgMiAwIFIgL1R5cGUgL0NhdGFsb2cg" +
	"Pj4KZW5kb2JqCjIgMCBvYmoKPDwgL0NvdW50IDEgL0tpZHMgWyAzIDAgUiBdIC9UeXBlIC9Q" +
	"YWdlcyA+PgplbmRvYmoKMyAwIG9iago8PCAvQ29udGVudHMgNCAwIFIgL01lZGlhQm94IFsg" +
	"MCAwIDYxMiA3OTIgXSAvUGFyZW50IDIgMCBSIC9SZXNvdXJjZXMgPDwgPj4gL1R5cGUgL1Bh" +
	"Z2UgPj4KZW5kb2JqCjQgMCBvYmoKPDwgL0xlbmd0aCAzMiAvRmlsdGVyIC9GbGF0ZURlY29k" +
	"ZSA+PgpzdHJlYW0KCKFdXDHIpzTbSCVQzr8fPofLIVm7Haubtb4Xa2PFsBYKZW5kc3RyZWFt" +
	"CmVuZG9iago1IDAgb2JqCjw8IC9DRiA8PCAvU3RkQ0YgPDwgL0F1dGhFdmVudCAvRG9jT3Bl" +
	"biAvQ0ZNIC9BRVNWMiAvTGVuZ3RoIDE2ID4+ID4+IC9GaWx0ZXIgL1N0YW5kYXJkIC9MZW5n" +
	"dGggMTI4IC9PIDxmODUwY2JiNTA1Y2FjNzhmOTNlODMxYjlmNmFhZjliZjU2NmVlY2I0ZTlk" +
	"MDljMjgzNDQwNjk1NDI0ODA1MDIzPiAvT0UgPD4gL1AgLTEwMjggL1IgNCAvU3RtRiAvU3Rk" +
	"Q0YgL1N0ckYgL1N0ZENGIC9VIDxhYzg1YTQ3ZWJmY2QxNzVhMTk1MmQ3M2FiYjVmOWRkYzAw" +
	"MjE0NDY5OTBiOWU0MTE0MDcxYTRkOTEwNDk4NGMxPiAvVUUgPD4gL1YgNCA+PgplbmRvYmoK" +
	"eHJlZgowIDYKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAwMDAwMDE1IDAwMDAwIG4gCjAwMDAw" +
	"MDAwNjQgMDAwMDAgbiAKMDAwMDAwMDEyMyAwMDAwMCBuIAowMDAwMDAwMjI5IDAwMDAwIG4g" +
	"CjAwMDAwMDAzMzIgMDAwMDAgbiAKdHJhaWxlciA8PCAvUm9vdCAxIDAgUiAvU2l6ZSA2IC9J" +
	"RCBbPGViNDdhMzc4ZmYwZDQ1YTc0ZjM5NjhiODE3M2QzOGI1PjxlYjQ3YTM3OGZmMGQ0NWE3" +
	"NGYzOTY4YjgxNzNkMzhiNT5dIC9FbmNyeXB0IDUgMCBSID4+CnN0YXJ0eHJlZgo2NDgKJSVF" +
	"T0YK"

const pdfAES256 = "JVBERi0xLjcKJb/3ov4KMSAwIG9iago8PCAvRXh0ZW5zaW9ucyA8PCAvQURCRSA8PCAvQmFz" +
	"ZVZlcnNpb24gLzEuNyAvRXh0ZW5zaW9uTGV2ZWwgOCA+PiA+PiAvUGFnZXMgMiAwIFIgL1R5" +
	"cGUgL0NhdGFsb2cgPj4KZW5kb2JqCjIgMCBvYmoKPDwgL0NvdW50IDEgL0tpZHMgWyAzIDAg" +
	"UiBdIC9UeXBlIC9QYWdlcyA+PgplbmRvYmoKMyAwIG9iago8PCAvQ29udGVudHMgNCAwIFIg" +
	"L01lZGlhQm94IFsgMCAwIDYxMiA3OTIgXSAvUGFyZW50IDIgMCBSIC9SZXNvdXJjZXMgPDwg" +
	"Pj4gL1R5cGUgL1BhZ2UgPj4KZW5kb2JqCjQgMCBvYmoKPDwgL0xlbmd0aCAzMiAvRmlsdGVy" +
	"IC9GbGF0ZURlY29kZSA+PgpzdHJlYW0K6k4CQYSijDfM6uDlH3+wQhcw4Dj2Spelp4kK6y0c" +
	"K28KZW5kc3RyZWFtCmVuZG9iago1IDAgb2JqCjw8IC9DRiA8PCAvU3RkQ0YgPDwgL0F1dGhF" +
	"dmVudCAvRG9jT3BlbiAvQ0ZNIC9BRVNWMyAvTGVuZ3RoIDMyID4+ID4+IC9GaWx0ZXIgL1N0" +
	"YW5kYXJkIC9MZW5ndGggMjU2IC9PIDxlN2ZjYzdiMDlmNjgyMzg0OTVhODFjN2JmYmM3OWQ1" +
	"OGJjM2YwNDEyYzljMTRmNmJkNmY5MjA3M2M3NDc4NDY2ZWIzMGNlZDEwOGIyNmFhNjMwZGE2" +
	"OTZkMmVjYmRkZDI+IC9PRSA8NjZjODJiNTRlZGY2MzRjM2RjYzAwZDRjMDNiY2UzZjY4MzYy" +
	"OTJkYjdhMTZlNTQwYjUwZDVkNDM4YmI4NGZiMT4gL1AgLTEwMjggL1Blcm1zIDxjMzYxODk4" +
	"MGM4OWYxZTAyMzZlYjZiNTE3NTY5YzA5Mz4gL1IgNiAvU3RtRiAvU3RkQ0YgL1N0ckYgL1N0" +
	"ZENGIC9VIDw2ZmU4MWNjNmRkNDk5MzEzYThlNmMxZDEyYzQzY2IxYTM3YzUxYjFlMmM1NWYw" +
	"YWE5ZjJlZDQ5NGI3NDcyY2Q2OGI1ZGY3MzllNjU1NjAwNGE3MTIzMWJlNmVjZDg1NzE+IC9V" +
	"RSA8ZWVkMDg1YzkxOTUyZmZlZTM1NzY5YjBlNzkwZWM4ZDlkN2RlNzNkMmE5MDk3NGQ5ZGRl" +
	"OTJjYjQ1Mjk0OWZhMj4gL1YgNSA+PgplbmRvYmoKeHJlZgowIDYKMDAwMDAwMDAwMCA2NTUz" +
	"NSBmIAowMDAwMDAwMDE1IDAwMDAwIG4gCjAwMDAwMDAxMzAgMDAwMDAgbiAKMDAwMDAwMDE4" +
	"OSAwMDAwMCBuIAowMDAwMDAwMjk1IDAwMDAwIG4gCjAwMDAwMDAzOTggMDAwMDAgbiAKdHJh" +
	"aWxlciA8PCAvUm9vdCAxIDAgUiAvU2l6ZSA2IC9JRCBbPGViNDdhMzc4ZmYwZDQ1YTc0ZjM5" +
	"NjhiODE3M2QzOGI1PjxlYjQ3YTM3OGZmMGQ0NWE3NGYzOTY4YjgxNzNkMzhiNT5dIC9FbmNy" +
	"eXB0IDUgMCBSID4+CnN0YXJ0eHJlZgo5NDgKJSVFT0YK"

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	return b
}

func TestDecode_RC4(t *testing.T) {
	r, err := Decode(mustB64(t, pdfRC4))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.Encrypted || r.SecurityHandler != "Standard" {
		t.Fatalf("encrypted=%v handler=%q", r.Encrypted, r.SecurityHandler)
	}
	if r.V != 4 || r.R != 4 || r.KeyBits != 128 {
		t.Errorf("V/R/bits = %d/%d/%d, want 4/4/128", r.V, r.R, r.KeyBits)
	}
	if r.Cipher != "RC4-128" || r.HashcatMode != 10500 {
		t.Errorf("cipher/mode = %q/%d, want RC4-128/10500", r.Cipher, r.HashcatMode)
	}
	if r.Permissions != -1028 {
		t.Errorf("permissions = %d, want -1028", r.Permissions)
	}
}

func TestDecode_AES128(t *testing.T) {
	r, err := Decode(mustB64(t, pdfAES128))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.V != 4 || r.R != 4 || r.KeyBits != 128 {
		t.Errorf("V/R/bits = %d/%d/%d, want 4/4/128", r.V, r.R, r.KeyBits)
	}
	if r.Cipher != "AES-128" || r.HashcatMode != 10600 {
		t.Errorf("cipher/mode = %q/%d, want AES-128/10600", r.Cipher, r.HashcatMode)
	}
}

func TestDecode_AES256(t *testing.T) {
	r, err := Decode(mustB64(t, pdfAES256))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.V != 5 || r.R != 6 || r.KeyBits != 256 {
		t.Errorf("V/R/bits = %d/%d/%d, want 5/6/256", r.V, r.R, r.KeyBits)
	}
	if r.Cipher != "AES-256" || r.HashcatMode != 10700 {
		t.Errorf("cipher/mode = %q/%d, want AES-256/10700", r.Cipher, r.HashcatMode)
	}
	if r.PDFVersion != "1.7" {
		t.Errorf("pdf version = %q, want 1.7", r.PDFVersion)
	}
}

func TestDecode_Unencrypted(t *testing.T) {
	pdf := []byte("%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF")
	r, err := Decode(pdf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Encrypted || r.HashcatMode != 0 {
		t.Errorf("encrypted=%v mode=%d, want false/0", r.Encrypted, r.HashcatMode)
	}
}

func TestDecode_Errors(t *testing.T) {
	for name, raw := range map[string][]byte{
		"empty":   {},
		"not pdf": []byte("this is not a pdf"),
	} {
		if _, err := Decode(raw); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(mustB64NoT(pdfRC4))
	f.Add(mustB64NoT(pdfAES256))
	f.Add([]byte("%PDF-1.7\n/Filter /Standard /V 4 /R 4"))
	f.Add([]byte("%PDF-"))
	f.Fuzz(func(_ *testing.T, raw []byte) {
		_, _ = Decode(raw)
	})
}

func mustB64NoT(s string) []byte { b, _ := base64.StdEncoding.DecodeString(s); return b }
