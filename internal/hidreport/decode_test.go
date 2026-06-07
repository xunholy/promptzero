// SPDX-License-Identifier: AGPL-3.0-or-later

package hidreport

import (
	"strings"
	"testing"
)

// The canonical USB HID boot-keyboard report descriptor (USB HID 1.11 App. E.6).
const bootKeyboard = "05010906a1010507" + "19e029e7" + "15002501" + "75019508" +
	"81029501" + "75088101" + "95057501" + "05081901" + "29059102" + "95017503" +
	"91019506" + "75081500" + "25650507" + "19002965" + "8100" + "c0"

func TestBootKeyboardDeclaresKeyboard(t *testing.T) {
	r, err := Decode(bootKeyboard)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// First three items: Usage Page (Generic Desktop), Usage (Keyboard),
	// Collection (Application).
	if r.Items[0].Tag != "Usage Page" || r.Items[0].Detail != "Generic Desktop" {
		t.Errorf("item0 = %+v", r.Items[0])
	}
	if r.Items[1].Tag != "Usage" || r.Items[1].Detail != "Keyboard" {
		t.Errorf("item1 = %+v", r.Items[1])
	}
	if r.Items[2].Tag != "Collection" || r.Items[2].Detail != "Application" {
		t.Errorf("item2 = %+v", r.Items[2])
	}
	// DeclaredUsages includes the keyboard, and the BadUSB note fires.
	foundUsage := false
	for _, u := range r.DeclaredUsages {
		if u == "Generic Desktop / Keyboard" {
			foundUsage = true
		}
	}
	if !foundUsage {
		t.Errorf("DeclaredUsages = %v, want 'Generic Desktop / Keyboard'", r.DeclaredUsages)
	}
	foundNote := false
	for _, n := range r.Notes {
		if strings.Contains(n, "BadUSB") {
			foundNote = true
		}
	}
	if !foundNote {
		t.Error("expected a BadUSB note for the declared keyboard")
	}
	// The last item is End Collection.
	last := r.Items[len(r.Items)-1]
	if last.Tag != "End Collection" {
		t.Errorf("last item = %q, want End Collection", last.Tag)
	}
}

func TestInputItemFlags(t *testing.T) {
	r, err := Decode(bootKeyboard)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// Find the first Input item (81 02 = Data, Variable, Absolute).
	var found *Item
	for i := range r.Items {
		if r.Items[i].Tag == "Input" {
			found = &r.Items[i]
			break
		}
	}
	if found == nil {
		t.Fatal("no Input item found")
	}
	if found.Detail != "Data,Variable,Absolute" {
		t.Errorf("Input flags = %q, want Data,Variable,Absolute", found.Detail)
	}
}

func TestMouseNoBadUSBNote(t *testing.T) {
	// Usage Page (Generic Desktop), Usage (Mouse), Collection (Application), End.
	r, err := Decode("05010902a101c0")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	foundMouse := false
	for _, u := range r.DeclaredUsages {
		if u == "Generic Desktop / Mouse" {
			foundMouse = true
		}
	}
	if !foundMouse {
		t.Errorf("DeclaredUsages = %v, want 'Generic Desktop / Mouse'", r.DeclaredUsages)
	}
	for _, n := range r.Notes {
		if strings.Contains(n, "BadUSB") {
			t.Error("a mouse descriptor should not trigger the BadUSB note")
		}
	}
}

func TestReportSizeCountValues(t *testing.T) {
	// 75 08 = Report Size 8; 95 06 = Report Count 6.
	r, err := Decode("75089506")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Items[0].Tag != "Report Size" || r.Items[0].Value == nil || *r.Items[0].Value != 8 {
		t.Errorf("item0 = %+v", r.Items[0])
	}
	if r.Items[1].Tag != "Report Count" || r.Items[1].Value == nil || *r.Items[1].Value != 6 {
		t.Errorf("item1 = %+v", r.Items[1])
	}
}

func TestTruncatedItemStops(t *testing.T) {
	// 05 01 (Usage Page, complete) then 26 ff (Logical Maximum claims 2 data
	// bytes but only 1 follows) — the walk decodes the first item and stops.
	r, err := Decode("050126ff")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Items) != 1 {
		t.Errorf("got %d items, want 1 (truncated second item dropped)", len(r.Items))
	}
}

func TestErrors(t *testing.T) {
	for _, in := range []string{"", "zz"} {
		if _, err := Decode(in); err == nil {
			t.Errorf("Decode(%q) expected error", in)
		}
	}
}
