// SPDX-License-Identifier: AGPL-3.0-or-later

package epc

import "testing"

func TestDecode_GID96_Vectors(t *testing.T) {
	cases := []struct {
		hex                       string
		manager, objClass, serial uint64
		tagURI                    string
	}{
		{"3500079FF00000B00000000C", 31231, 11, 12, "urn:epc:tag:gid-96:31231.11.12"},
		{"3500E82D900000F000000001", 951001, 15, 1, "urn:epc:tag:gid-96:951001.15.1"},
		{"350000A2600019003ADE56FA", 2598, 400, 987649786, "urn:epc:tag:gid-96:2598.400.987649786"},
	}
	for _, c := range cases {
		r, err := DecodeHex(c.hex)
		if err != nil {
			t.Fatalf("%s: %v", c.hex, err)
		}
		if r.Scheme != "GID-96" {
			t.Errorf("%s: scheme = %s, want GID-96", c.hex, r.Scheme)
		}
		g := r.GID
		if g == nil {
			t.Fatalf("%s: GID not decoded", c.hex)
		}
		if g.GeneralManagerNumber != c.manager || g.ObjectClass != c.objClass || g.SerialNumber != c.serial {
			t.Errorf("%s: got %d.%d.%d, want %d.%d.%d", c.hex,
				g.GeneralManagerNumber, g.ObjectClass, g.SerialNumber, c.manager, c.objClass, c.serial)
		}
		if g.TagURI != c.tagURI {
			t.Errorf("%s: tag URI = %q, want %q", c.hex, g.TagURI, c.tagURI)
		}
	}
}

func TestDecode_GID96_PureIdentityURI(t *testing.T) {
	r, _ := DecodeHex("3500079FF00000B00000000C")
	if r.GID.PureIdentityURI != "urn:epc:id:gid:31231.11.12" {
		t.Errorf("pure identity URI = %q", r.GID.PureIdentityURI)
	}
}
