// Package mqtt is PromptZero's publish-only MQTT bridge. When enabled
// via config, it mirrors agent lifecycle state to an operator's broker
// so downstream automations (Home Assistant, Node-RED, dashboards) can
// react to tool runs, risk prompts, and audit-critical events without
// polling or needing API credentials.
//
// Topic layout (BasePath defaults to "promptzero"):
//
//	<base>/state/online                — retained LWT, "true" / "false"
//	<base>/events/<event_name>         — per-lifecycle event JSON
//	<base>/tools/<tool_name>/last      — retained last tool output/args
//	<base>/audit/critical              — audit rows at level=critical
//
// The bridge is strictly publish-only. Startup never blocks: if the
// broker is unreachable, Connect returns the underlying error but the
// Paho client's auto-reconnect keeps trying in the background. All
// public methods are safe to call before Connected() returns true —
// messages published while disconnected are dropped with a log line
// rather than queued (operators care about present state, not history).
package mqtt

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"

	"github.com/xunholy/promptzero/internal/config"
)

// Client is the Paho subset this package uses. Extracted so tests can
// substitute a mock without opening a real broker connection.
type Client interface {
	Connect() Token
	Disconnect(quiesceMs uint)
	IsConnected() bool
	Publish(topic string, qos byte, retained bool, payload interface{}) Token
}

// Token is the Paho subset we need for publish/connect acknowledgements.
type Token interface {
	Wait() bool
	WaitTimeout(time.Duration) bool
	Error() error
}

// Factory builds a Client from Paho options. Injected so tests can swap
// in a mock constructor via NewWithFactory.
type Factory func(opts *paho.ClientOptions) Client

// defaultFactory wraps paho.NewClient so its concrete return type implements
// our Client interface (it already matches by structural typing).
func defaultFactory(opts *paho.ClientOptions) Client {
	return pahoAdapter{c: paho.NewClient(opts)}
}

// pahoAdapter wraps the real Paho client's Publish/Connect so the returned
// paho.Token values satisfy our Token interface. Paho's Token is already
// compatible structurally, but wrapping keeps imports scoped to this file.
type pahoAdapter struct{ c paho.Client }

func (a pahoAdapter) Connect() Token                { return a.c.Connect() }
func (a pahoAdapter) Disconnect(quiesceMs uint)     { a.c.Disconnect(quiesceMs) }
func (a pahoAdapter) IsConnected() bool             { return a.c.IsConnected() }
func (a pahoAdapter) Publish(topic string, qos byte, retained bool, payload interface{}) Token {
	return a.c.Publish(topic, qos, retained, payload)
}

// Bridge is the outward-facing publish handle. When Enabled=false in config,
// New returns a zero-value Bridge whose methods are no-ops, so callers don't
// branch on nil.
type Bridge struct {
	cfg      config.MQTTConfig
	client   Client
	base     string
	qos      byte
	retained bool

	mu       sync.Mutex
	enabled  bool
	lastErr  error
}

// defaultBase is used when MQTTConfig.BasePath is empty.
const defaultBase = "promptzero"

// maxPayloadBytes caps individual publish bodies. The "last tool output"
// topic can grab verbose tool responses; trimming keeps the broker happy
// and matches Home Assistant's recorder-friendly size.
const maxPayloadBytes = 1024

// New constructs a Bridge using the default (real Paho) factory. If
// cfg.Enabled is false or Broker is empty, the returned bridge is a
// no-op — callers don't need to check before calling Publish/Close.
func New(cfg config.MQTTConfig) *Bridge {
	return NewWithFactory(cfg, defaultFactory)
}

// NewWithFactory is the injection point for tests. Pass a factory that
// returns a mock Client to avoid opening a real broker.
func NewWithFactory(cfg config.MQTTConfig, factory Factory) *Bridge {
	b := &Bridge{cfg: cfg, qos: cfg.QoS, retained: cfg.Retained}
	b.base = strings.Trim(cfg.BasePath, "/")
	if b.base == "" {
		b.base = defaultBase
	}
	if !cfg.Enabled || cfg.Broker == "" {
		return b
	}
	opts := paho.NewClientOptions().
		AddBroker(cfg.Broker).
		SetClientID(cfg.ClientID).
		SetUsername(cfg.Username).
		SetPassword(cfg.Password).
		SetAutoReconnect(true).
		SetKeepAlive(30 * time.Second).
		SetCleanSession(true).
		SetConnectRetry(true).
		SetConnectRetryInterval(5 * time.Second).
		SetMaxReconnectInterval(2 * time.Minute).
		SetWill(b.base+"/state/online", "false", cfg.QoS, true).
		SetOnConnectHandler(func(_ paho.Client) {
			b.publishRaw(b.base+"/state/online", []byte("true"), true)
		})
	b.client = factory(opts)
	b.enabled = true
	return b
}

// Connect starts the broker session. Non-blocking: returns whatever the
// first connect attempt surfaces (nil on success, the connection error
// otherwise). Auto-reconnect continues in the background regardless.
func (b *Bridge) Connect() error {
	if b == nil || !b.enabled || b.client == nil {
		return nil
	}
	tok := b.client.Connect()
	if !tok.WaitTimeout(5 * time.Second) {
		b.setErr(fmt.Errorf("mqtt connect timeout"))
		return b.lastErr
	}
	if err := tok.Error(); err != nil {
		b.setErr(err)
		return err
	}
	b.setErr(nil)
	return nil
}

// Close flips state/online to "false" (retained so subscribers see the
// current state on reconnect) and disconnects the client.
func (b *Bridge) Close() {
	if b == nil || !b.enabled || b.client == nil {
		return
	}
	if b.client.IsConnected() {
		b.publishRaw(b.base+"/state/online", []byte("false"), true)
	}
	b.client.Disconnect(500)
}

// Connected reports whether the client is currently attached to the
// broker. Used by /mqtt to surface status.
func (b *Bridge) Connected() bool {
	if b == nil || !b.enabled || b.client == nil {
		return false
	}
	return b.client.IsConnected()
}

// LastError returns the most recent connection or publish error (for
// /mqtt introspection). Cleared on successful connect.
func (b *Bridge) LastError() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastErr
}

// Enabled reports whether the bridge was configured to publish at all.
func (b *Bridge) Enabled() bool { return b != nil && b.enabled }

// BasePath returns the configured (or default) topic prefix.
func (b *Bridge) BasePath() string {
	if b == nil {
		return defaultBase
	}
	return b.base
}

// PublishEvent mirrors a lifecycle event onto <base>/events/<event>.
// Payload is JSON-marshalled; non-marshallable payloads are logged and
// dropped silently.
func (b *Bridge) PublishEvent(event string, payload any) {
	if b == nil || !b.enabled {
		return
	}
	body := marshal(payload)
	if body == nil {
		return
	}
	b.publishRaw(b.base+"/events/"+sanitize(event), body, false)
}

// PublishToolLast mirrors the last run of a named tool onto
// <base>/tools/<tool>/last as a retained message so new subscribers
// see the current tail without waiting for the next event.
func (b *Bridge) PublishToolLast(tool string, payload any) {
	if b == nil || !b.enabled {
		return
	}
	body := marshal(payload)
	if body == nil {
		return
	}
	b.publishRaw(b.base+"/tools/"+sanitize(tool)+"/last", body, true)
}

// PublishAuditCritical mirrors a critical audit row onto
// <base>/audit/critical. Non-retained — operators who care consume the
// stream; late joiners rely on the audit DB.
func (b *Bridge) PublishAuditCritical(payload any) {
	if b == nil || !b.enabled {
		return
	}
	body := marshal(payload)
	if body == nil {
		return
	}
	b.publishRaw(b.base+"/audit/critical", body, false)
}

// publishRaw is the single choke point where QoS, truncation, and the
// "skip if disconnected" check live. We deliberately drop rather than
// queue — the event stream is informational, not a message bus.
func (b *Bridge) publishRaw(topic string, body []byte, retained bool) {
	if b.client == nil {
		return
	}
	if !b.client.IsConnected() {
		log.Printf("mqtt: drop %s (disconnected)", topic)
		return
	}
	if len(body) > maxPayloadBytes {
		body = append(body[:maxPayloadBytes-len("... [truncated]")], []byte("... [truncated]")...)
	}
	tok := b.client.Publish(topic, b.qos, retained || b.retained, body)
	go func() {
		if !tok.WaitTimeout(2 * time.Second) {
			b.setErr(fmt.Errorf("mqtt publish %s timeout", topic))
			return
		}
		if err := tok.Error(); err != nil {
			b.setErr(fmt.Errorf("mqtt publish %s: %w", topic, err))
		}
	}()
}

// setErr atomically updates the last-error field seen by /mqtt.
func (b *Bridge) setErr(err error) {
	b.mu.Lock()
	b.lastErr = err
	b.mu.Unlock()
}

// marshal is a small wrapper so a JSON error is logged in one place and
// callers receive nil (treated as "drop").
func marshal(v any) []byte {
	body, err := json.Marshal(v)
	if err != nil {
		log.Printf("mqtt: marshal: %v", err)
		return nil
	}
	return body
}

// sanitize trims topic segments to the MQTT-safe subset. MQTT allows
// most bytes but +, # and / would be interpreted as wildcards or level
// separators — strip them so user-supplied names (tool, event) can't
// escape their intended topic segment.
func sanitize(s string) string {
	s = strings.TrimSpace(s)
	r := strings.NewReplacer("+", "_", "#", "_", "/", "_", " ", "_")
	return r.Replace(s)
}
