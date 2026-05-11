package flipper

import (
	"strings"
	"testing"
)

// TestInputSend_RejectsUnknownButton pins the v0.179 contract: button
// is validated against an allowlist (up, down, left, right, ok, back)
// before any transport dispatch. Pre-fix only eventType was checked, so
// a typo in button reached the firmware as an unrecognised arg — the
// LLM then saw an opaque firmware error instead of clean feedback.
//
// We use a Flipper{} with no transport on purpose: button validation
// must run BEFORE any dispatch, so the test never reaches the panic
// path of trying to send to a nil transport.
func TestInputSend_RejectsUnknownButton(t *testing.T) {
	f := &Flipper{}
	cases := []string{
		"OK",   // case-sensitive — uppercase rejected
		"foo",  // not a button
		"",     // empty
		"up ",  // trailing space slips past sanitizeArg
		"\tup", // leading tab slips past sanitizeArg
	}
	for _, button := range cases {
		t.Run(button, func(t *testing.T) {
			_, err := f.InputSend(button, "press")
			if err == nil {
				t.Fatalf("expected error for button %q; got nil", button)
			}
			if !strings.Contains(err.Error(), "button") {
				t.Errorf("err = %v; want 'button' validation error", err)
			}
		})
	}
}

// TestInputSend_RejectsUnknownEventType verifies the pre-existing
// eventType check still fires and now also runs after the new button
// check.
func TestInputSend_RejectsUnknownEventType(t *testing.T) {
	f := &Flipper{}
	_, err := f.InputSend("up", "repeat") // "repeat" was never in the allowlist
	if err == nil {
		t.Fatal("expected error for unknown eventType; got nil")
	}
	if !strings.Contains(err.Error(), "eventType") {
		t.Errorf("err = %v; want eventType validation error", err)
	}
}

// TestInputSend_BadButtonNotEventType verifies button validation runs
// first: a request with both arguments invalid must surface the button
// error, not the eventType error.
func TestInputSend_BadButtonNotEventType(t *testing.T) {
	f := &Flipper{}
	_, err := f.InputSend("foo", "repeat")
	if err == nil {
		t.Fatal("expected error; got nil")
	}
	if !strings.Contains(err.Error(), "button") {
		t.Errorf("err = %v; want button error first (precedes eventType)", err)
	}
}
