package workflows

import "testing"

// TestParamInt_GoNativeNumericTypes pins the v0.158 extension that
// brings paramInt onto the v0.157 tools.intOr contract: in addition
// to the JSON-default float64 and the existing int + string branches,
// the helper now accepts int32 / int64 / float32 inputs. Production
// hits these for free via the JSON round-trip path (float64), but
// internal callers building the param map directly without that
// round-trip previously silently got the fallback for any Go-native
// numeric type that wasn't plain int.
func TestParamInt_GoNativeNumericTypes(t *testing.T) {
	cases := []struct {
		name string
		val  any
		want int
	}{
		{"go_int", int(42), 42},
		{"go_int32", int32(-7), -7},
		{"go_int64", int64(123456), 123456},
		{"go_float32", float32(3.9), 3}, // float→int truncation
		{"json_float64", float64(99), 99},
		{"numeric_string", "100", 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := map[string]any{"k": tc.val}
			if got := paramInt(p, "k", -1); got != tc.want {
				t.Errorf("paramInt(%v) = %d, want %d", tc.val, got, tc.want)
			}
		})
	}
}

// TestParamInt_FallbackPath verifies the docstring's "absent or
// unparseable" fallback contract for keys that aren't present and
// for value types that don't match the numeric set.
func TestParamInt_FallbackPath(t *testing.T) {
	cases := []struct {
		name string
		val  any
	}{
		{"missing", nil}, // we'll skip the Put so the key is absent
		{"bool", true},
		{"empty_string", ""},
		{"non_numeric_string", "not-a-number"},
		{"slice", []int{1, 2, 3}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := map[string]any{}
			if tc.name != "missing" {
				p["k"] = tc.val
			}
			if got := paramInt(p, "k", 999); got != 999 {
				t.Errorf("paramInt(%v) = %d, want fallback 999", tc.val, got)
			}
		})
	}
}

// TestParamIntList_GoNativeNumericTypes pins the same v0.158 contract
// on the array variant. Mixed-type arrays are useful: a JSON-decoded
// list and an internal-Go-built list should both flatten to []int
// regardless of element type.
func TestParamIntList_GoNativeNumericTypes(t *testing.T) {
	p := map[string]any{
		"mixed": []any{
			float64(1), // json default
			float32(2), // go-native
			int(3),     // go-native
			int32(4),   // go-native
			int64(5),   // go-native
			"6",        // numeric string
			"notanum",  // skipped
			true,       // skipped
		},
	}
	got := paramIntList(p, "mixed")
	want := []int{1, 2, 3, 4, 5, 6}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (got %v)", len(got), len(want), got)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("[%d] = %d, want %d", i, got[i], v)
		}
	}
}
