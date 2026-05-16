package workflows

import (
	"reflect"
	"testing"
)

// firstLine and paramStringList are pure helpers feeding the badge_walk,
// hw_recon, badusb_profile, nfc_badge, and wifi_hashcat workflows. Both
// were at 0% coverage — quiet drift in either would produce silently
// wrong workflow summaries or drop user-supplied GPIO lists.

func TestFirstLine_HappyPaths(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"single line", "single line"},
		{"first\nsecond", "first"},
		{"\nfirst real\nsecond\n", "first real"},
		{"   leading-ws\nrest", "leading-ws"},
		{"trailing-ws   \nrest", "trailing-ws"},
		{"\n\n\nmiddle\nlast", "middle"},
	}
	for _, c := range cases {
		if got := firstLine(c.in); got != c.want {
			t.Errorf("firstLine(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestFirstLine_EmptyAndAllWhitespace(t *testing.T) {
	cases := []string{
		"",
		"\n",
		"\n\n\n",
		"   ",
		"\t\t\n   \n",
	}
	for _, in := range cases {
		if got := firstLine(in); got != "" {
			t.Errorf("firstLine(%q) = %q; want empty", in, got)
		}
	}
}

func TestParamStringList_Present(t *testing.T) {
	p := map[string]interface{}{
		"gpios": []interface{}{"PA4", "PA6", "PA7"},
	}
	got := paramStringList(p, "gpios")
	want := []string{"PA4", "PA6", "PA7"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("paramStringList = %v; want %v", got, want)
	}
}

func TestParamStringList_MissingKey(t *testing.T) {
	p := map[string]interface{}{"other": []interface{}{"a"}}
	if got := paramStringList(p, "gpios"); got != nil {
		t.Errorf("paramStringList missing key = %v; want nil", got)
	}
}

func TestParamStringList_WrongType(t *testing.T) {
	cases := []map[string]interface{}{
		{"gpios": "PA4"},            // string, not []interface{}
		{"gpios": 42},               // int
		{"gpios": map[string]int{}}, // map
		{"gpios": nil},              // nil — type assert fails
	}
	for _, p := range cases {
		if got := paramStringList(p, "gpios"); got != nil {
			t.Errorf("paramStringList(wrong type) = %v; want nil for input %v", got, p)
		}
	}
}

func TestParamStringList_FiltersNonStrings(t *testing.T) {
	// JSON arrays often contain mixed types after decode. Non-strings
	// are silently dropped, not type-coerced.
	p := map[string]interface{}{
		"gpios": []interface{}{"PA4", 42, "PA6", true, "PA7", nil},
	}
	got := paramStringList(p, "gpios")
	want := []string{"PA4", "PA6", "PA7"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("paramStringList filtered = %v; want %v", got, want)
	}
}

func TestParamStringList_EmptyArray(t *testing.T) {
	p := map[string]interface{}{"gpios": []interface{}{}}
	got := paramStringList(p, "gpios")
	if got == nil {
		t.Error("paramStringList(empty array) returned nil; want non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("paramStringList(empty array) = %v; want len 0", got)
	}
}
