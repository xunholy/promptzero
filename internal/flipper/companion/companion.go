// Package companion is the optional Flipper-side status renderer for
// the agent loop. The host emits small JSON events ("busy", "done",
// "confirm", "idle") that the on-device PromptZero Companion FAP reads
// from SD card and renders on the OLED so the operator can see, at a
// glance, what the agent is doing to the device they're holding.
//
// Optional by design. When the FAP is not installed (or the operator
// disabled the integration in config) the host wires a NopSink and
// every existing flow runs unchanged. There is no hard dependency on
// the on-device side — the host writes a status file and forgets;
// whether anything reads it is the FAP's problem.
//
// Wire format (status.json on SD):
//
//	{"v":1,"t":"busy","label":"subghz_tx","detail":"433.92 MHz","risk":"high","ts":1714060801}
//	{"v":1,"t":"done","label":"subghz_tx","ok":true,"ts":1714060802}
//	{"v":1,"t":"confirm","label":"wifi_deauth","risk":"critical","ts":1714060900}
//	{"v":1,"t":"idle","ts":1714060920}
//
// The on-device side polls the file, parses the latest event, and
// updates the screen. Old events are simply overwritten.
package companion

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"time"
)

// NewID returns a fresh short token suitable for tagging a confirm
// event so the matching response from the FAP can be filtered out
// of any stale answers. Eight hex chars give 4 bn possibilities —
// far more than needed when the host only has a handful of
// outstanding confirms in flight at once. Not security-sensitive:
// a collision just means one user-visible "no answer received"
// fall-through, recoverable on the next prompt.
func NewID() string {
	return fmt.Sprintf("%08x", rand.Uint32())
}

// WireVersion is bumped if the on-device parser stops being able to
// read events written by older hosts. Today both sides treat any v=1
// event as parseable; reserved for future evolution.
const WireVersion = 1

// DefaultStatusPath is where FlipperSink writes by default. Matches
// the FAP's polled location. Override via FlipperSink.Path if both
// sides agree.
const DefaultStatusPath = "/ext/apps_data/promptzero_companion/status.json"

// DefaultResponsePath is where the FAP writes operator decisions
// (approve/deny on confirm prompts). The host-side poller reads
// this file when confirm responses are enabled.
const DefaultResponsePath = "/ext/apps_data/promptzero_companion/response.json"

// EventType is the discriminator the FAP switches on when rendering.
// Kept as a small string set so the on-device parser can compare
// without a real JSON-schema lookup.
type EventType string

const (
	EventIdle    EventType = "idle"
	EventBusy    EventType = "busy"
	EventConfirm EventType = "confirm"
	EventDone    EventType = "done"
)

// Event is the wire-format payload. Field names are short to keep
// the JSON small — the FAP parses ~200-byte payloads byte-by-byte
// from SD, every saved byte matters.
type Event struct {
	Version int       `json:"v"`
	Type    EventType `json:"t"`
	Label   string    `json:"label,omitempty"`
	Detail  string    `json:"detail,omitempty"`
	Risk    string    `json:"risk,omitempty"`
	OK      *bool     `json:"ok,omitempty"`
	// ID is set on Confirm events. The FAP echoes it in the
	// response file so the host can match the operator's answer
	// to the right outstanding request, ignoring stale or replayed
	// responses from prior confirms.
	ID string `json:"id,omitempty"`
	TS int64  `json:"ts"`
}

// Response is the operator's reply to a Confirm event, recorded by
// the FAP into the response file. ID matches the corresponding
// Event.ID; consumers MUST filter on ID and discard responses with
// no matching outstanding request.
type Response struct {
	ID       string `json:"id"`
	Decision string `json:"decision"` // "approve" | "deny"
}

// Approved returns true when the response carries an approve
// decision. Any other value (including the empty string) is
// treated as a deny so a malformed or partial write can never be
// interpreted as authorisation.
func (r Response) Approved() bool { return r.Decision == "approve" }

// Sink is the host-side abstraction the agent loop pushes events
// into. Implementations are expected to be non-blocking — the agent
// must not stall on a slow USB write — and safe for concurrent use.
//
// The set of methods is deliberately tiny. New event types should be
// added here so callers don't have to construct raw Events.
type Sink interface {
	// Idle signals "no active work, awaiting next prompt." The FAP
	// renders a calm header and clears any spinner.
	Idle()

	// Busy signals an in-flight tool call. Label is the short tool
	// name (e.g. "subghz_tx"). Detail is a one-line summary of the
	// most operator-relevant input field (e.g. "433.92 MHz").
	// RiskLevel is the lowercase risk.Level string ("low" / "medium"
	// / "high" / "critical"); the FAP uses it to colour the header.
	Busy(label, detail, riskLevel string)

	// Done signals the most recent Busy completed. ok=false means
	// the tool errored; the FAP renders an X mark.
	Done(label string, ok bool)

	// Confirm signals the agent is paused waiting for the operator
	// to approve a high-risk action. id is a fresh per-request
	// token the FAP echoes back in its response so the caller can
	// match the answer to this prompt and ignore any stale or
	// replayed responses from earlier confirms.
	Confirm(id, label, riskLevel string)

	// Responses returns a channel that delivers operator decisions
	// pushed by the FAP. The channel is alive for the sink's
	// lifetime; consumers MUST filter on the ID and discard any
	// response whose ID doesn't match an outstanding request.
	// Returns a never-firing channel for the NopSink.
	Responses() <-chan Response

	// PollResponses enables (true) or disables (false) the
	// background read loop that watches the FAP's response file.
	// Disabled by default — the wiring layer turns polling on for
	// the duration of a confirm wait and back off on return so the
	// USB link is quiet between prompts.
	PollResponses(enable bool)

	// Close releases any background workers. Idempotent.
	Close() error
}

// NopSink is the default when the FAP is not installed or the
// integration is disabled. Every method is a no-op — placed in this
// package (not setup.go) so callers always have a non-nil Sink and
// don't need nil-checks at every push site.
type NopSink struct{}

func (NopSink) Idle()                      {}
func (NopSink) Busy(_, _, _ string)        {}
func (NopSink) Done(_ string, _ bool)      {}
func (NopSink) Confirm(_, _, _ string)     {}
func (NopSink) Responses() <-chan Response { return nopResponseCh }
func (NopSink) PollResponses(_ bool)       {}
func (NopSink) Close() error               { return nil }

// nopResponseCh is shared across NopSink instances because every
// receive blocks forever — there is no value in handing each caller
// its own dead channel. Made package-level so tests can compare
// pointer identity if they care.
var nopResponseCh = make(chan Response)

// nowSeconds returns the current Unix time. Pulled out so tests can
// stub a deterministic clock.
var nowSeconds = func() int64 { return time.Now().Unix() }

// newEvent constructs an Event with the version and timestamp filled
// in. Callers in this package use it; external callers go through
// the Sink methods.
func newEvent(t EventType) Event {
	return Event{Version: WireVersion, Type: t, TS: nowSeconds()}
}

// EncodeEvent renders an Event to its wire-format JSON, terminated
// with a newline. Exposed for tests and for the FAP-build helper
// that ships a sample fixture; production callers go through Sink.
func EncodeEvent(e Event) ([]byte, error) {
	if e.Version == 0 {
		e.Version = WireVersion
	}
	if e.TS == 0 {
		e.TS = nowSeconds()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
