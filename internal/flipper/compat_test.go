package flipper

import (
	"errors"
	"strings"
	"testing"
)

// TestCommandRouteString covers the String() method on the route
// enum so log lines and error reasons stay stable. Mirrors the
// constant order in compat.go; if a new route is added without
// updating String(), this test fails.
func TestCommandRouteString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		route CommandRoute
		want  string
	}{
		{RouteTextCLI, "text-cli"},
		{RouteRPC, "rpc"},
		{RouteUSBOnly, "usb-only"},
	}
	for _, tc := range cases {
		if got := tc.route.String(); got != tc.want {
			t.Errorf("CommandRoute(%d).String() = %q, want %q", int(tc.route), got, tc.want)
		}
	}

	// Unknown values fall back to a descriptive form that includes
	// the integer value — useful for forward-compat debugging.
	if got := CommandRoute(99).String(); !strings.Contains(got, "99") {
		t.Errorf("CommandRoute(99).String() = %q, want a string containing the integer", got)
	}
}

// TestRouteFor table-tests every cell of the Phase A decision
// matrix plus the FirmwareForkRequired gate. Each row names the
// scenario, the inputs, and the route expected — when the route is
// USBOnly the test additionally asserts the Reason carries useful
// substring evidence so the agent layer's downstream message is
// stable.
func TestRouteFor(t *testing.T) {
	t.Parallel()

	type tc struct {
		name           string
		support        CommandSupport
		transportKind  string
		caps           Capabilities
		wantRoute      CommandRoute
		wantReasonSubs []string // substrings the Reason MUST contain (USB-only rows)
	}

	cases := []tc{
		// ── BLE half ────────────────────────────────────────────
		{
			name:          "ble + has rpc verb -> rpc",
			support:       CommandSupport{HasRPCVerb: true, HasCLI: true},
			transportKind: "ble",
			wantRoute:     RouteRPC,
		},
		{
			name:          "ble + has rpc verb only -> rpc (cli flag irrelevant)",
			support:       CommandSupport{HasRPCVerb: true, HasCLI: false},
			transportKind: "ble",
			wantRoute:     RouteRPC,
		},
		{
			name:           "ble + no rpc verb -> usb-only with explicit reason",
			support:        CommandSupport{HasRPCVerb: false, HasCLI: true},
			transportKind:  "ble",
			wantRoute:      RouteUSBOnly,
			wantReasonSubs: []string{"no RPC verb", "BLE"},
		},
		{
			name:           "ble + zero support -> usb-only",
			support:        CommandSupport{},
			transportKind:  "ble",
			wantRoute:      RouteUSBOnly,
			wantReasonSubs: []string{"no RPC verb"},
		},

		// ── USB-class half (serial / http / mock / "") ─────────
		{
			name:          "serial + has cli -> text-cli",
			support:       CommandSupport{HasRPCVerb: true, HasCLI: true},
			transportKind: "serial",
			wantRoute:     RouteTextCLI,
		},
		{
			name:          "serial + cli only -> text-cli",
			support:       CommandSupport{HasRPCVerb: false, HasCLI: true},
			transportKind: "serial",
			wantRoute:     RouteTextCLI,
		},
		{
			name:          "mock transport behaves as USB-class",
			support:       CommandSupport{HasRPCVerb: false, HasCLI: true},
			transportKind: "mock",
			wantRoute:     RouteTextCLI,
		},
		{
			name:          "empty transport kind treated as USB-class",
			support:       CommandSupport{HasRPCVerb: false, HasCLI: true},
			transportKind: "",
			wantRoute:     RouteTextCLI,
		},
		{
			name:           "serial + no cli -> usb-only with explicit reason",
			support:        CommandSupport{HasRPCVerb: true, HasCLI: false},
			transportKind:  "serial",
			wantRoute:      RouteUSBOnly,
			wantReasonSubs: []string{"no text-CLI"},
		},

		// ── FirmwareForkRequired gate ──────────────────────────
		{
			name:          "fork required and matches -> normal route (text-cli)",
			support:       CommandSupport{HasRPCVerb: false, HasCLI: true, FirmwareForkRequired: "Momentum"},
			transportKind: "serial",
			caps:          Capabilities{FirmwareFork: "Momentum"},
			wantRoute:     RouteTextCLI,
		},
		{
			name:          "fork required and matches case-insensitively -> normal route",
			support:       CommandSupport{HasRPCVerb: true, HasCLI: true, FirmwareForkRequired: "momentum"},
			transportKind: "ble",
			caps:          Capabilities{FirmwareFork: "MOMENTUM"},
			wantRoute:     RouteRPC,
		},
		{
			name:          "fork required but live device differs -> usb-only with mismatch reason",
			support:       CommandSupport{HasRPCVerb: true, HasCLI: true, FirmwareForkRequired: "Momentum"},
			transportKind: "serial",
			caps:          Capabilities{FirmwareFork: "Unleashed"},
			wantRoute:     RouteUSBOnly,
			// live label is lower-cased by RouteFor's case-insensitive comparison.
			wantReasonSubs: []string{"requires firmware fork", "Momentum", "unleashed"},
		},
		{
			name:           "fork required and live device is empty (stock) -> usb-only with stock label",
			support:        CommandSupport{HasRPCVerb: false, HasCLI: true, FirmwareForkRequired: "Momentum"},
			transportKind:  "serial",
			caps:           Capabilities{FirmwareFork: ""},
			wantRoute:      RouteUSBOnly,
			wantReasonSubs: []string{"requires firmware fork", "stock"},
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := RouteFor("op", c.support, c.transportKind, c.caps)
			if got.Route != c.wantRoute {
				t.Fatalf("RouteFor route = %v, want %v (reason=%q)", got.Route, c.wantRoute, got.Reason)
			}
			if got.Reason == "" {
				t.Errorf("RouteFor reason is empty; every decision should carry one")
			}
			for _, sub := range c.wantReasonSubs {
				if !strings.Contains(got.Reason, sub) {
					t.Errorf("RouteFor reason %q missing substring %q", got.Reason, sub)
				}
			}
		})
	}
}

// TestRouteForOperationNameInForkMismatch ensures the operation
// name passed in propagates into the user-visible reason on the
// fork-mismatch path. Errors surface to operators with the verb
// name attached, so this is a contract worth pinning.
func TestRouteForOperationNameInForkMismatch(t *testing.T) {
	t.Parallel()

	dec := RouteFor(
		"clear",
		CommandSupport{HasRPCVerb: false, HasCLI: true, FirmwareForkRequired: "Momentum"},
		"serial",
		Capabilities{FirmwareFork: "Unleashed"},
	)
	if dec.Route != RouteUSBOnly {
		t.Fatalf("Route = %v, want RouteUSBOnly", dec.Route)
	}
	if !strings.HasPrefix(dec.Reason, "clear ") {
		t.Errorf("expected reason to start with the operation name %q, got %q", "clear", dec.Reason)
	}
}

// TestDispatchUSBOnlyWrapsErrCommandRequiresUSB verifies the
// (string, error) shape of Flipper.dispatch when RouteFor returns
// USBOnly: the returned error must satisfy errors.Is against
// ErrCommandRequiresUSB so callers (and the agent layer) can
// detect "this needs USB" categorically.
//
// We use a *Flipper with transport=nil so transportKind() returns
// "" (USB-class) and CommandSupport{HasCLI: false} so the route
// resolves to USBOnly without us needing a real BLE transport.
func TestDispatchUSBOnlyWrapsErrCommandRequiresUSB(t *testing.T) {
	t.Parallel()

	f := &Flipper{}
	_, err := f.dispatch(
		"sub-ghz tx",
		CommandSupport{HasRPCVerb: true, HasCLI: false},
		func() (string, error) { return "should-not-run", nil },
		func() (string, error) { return "should-not-run", nil },
	)
	if err == nil {
		t.Fatal("dispatch returned nil error on USBOnly route, want ErrCommandRequiresUSB")
	}
	if !errors.Is(err, ErrCommandRequiresUSB) {
		t.Errorf("err = %v, want errors.Is(err, ErrCommandRequiresUSB)", err)
	}
	if !strings.Contains(err.Error(), "sub-ghz tx") {
		t.Errorf("err = %q, expected operation name to appear", err.Error())
	}
}

// TestDispatchInvokesCorrectClosure proves that the chosen closure
// is the one that actually runs. We rig two sentinels and verify
// the route picks the right one — without this the migration could
// silently swap branches and the higher-level mock tests wouldn't
// catch it.
func TestDispatchInvokesCorrectClosure(t *testing.T) {
	t.Parallel()

	cliSentinel := "from-cli"
	rpcSentinel := "from-rpc"

	cli := func() (string, error) { return cliSentinel, nil }
	rpc := func() (string, error) { return rpcSentinel, nil }

	// USB-class transport (transport==nil -> kind=="") with
	// HasCLI=true picks RouteTextCLI.
	f := &Flipper{}
	got, err := f.dispatch(
		"op",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		cli,
		rpc,
	)
	if err != nil {
		t.Fatalf("dispatch err = %v", err)
	}
	if got != cliSentinel {
		t.Errorf("dispatch on USB-class returned %q, want %q (CLI sentinel)", got, cliSentinel)
	}
}

// TestDispatchNilClosureReturnsError pins the "programming-mistake"
// guard rail: if the route resolves to RouteTextCLI but viaCLI is
// nil, dispatch must return a clear error rather than panic.
func TestDispatchNilClosureReturnsError(t *testing.T) {
	t.Parallel()

	f := &Flipper{}
	_, err := f.dispatch(
		"op",
		CommandSupport{HasRPCVerb: true, HasCLI: true},
		nil, // viaCLI missing
		func() (string, error) { return "", nil },
	)
	if err == nil {
		t.Fatal("dispatch returned nil error with nil viaCLI on text-cli route")
	}
	if !strings.Contains(err.Error(), "no CLI closure") {
		t.Errorf("err = %q, want a message mentioning the missing CLI closure", err.Error())
	}
}
