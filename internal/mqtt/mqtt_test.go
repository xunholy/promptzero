package mqtt

import (
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"

	"github.com/xunholy/promptzero/internal/config"
)

// mockToken is a Paho-compatible token that resolves immediately with a
// preset error. The zero value is "succeeded".
type mockToken struct{ err error }

func (m *mockToken) Wait() bool                     { return true }
func (m *mockToken) WaitTimeout(time.Duration) bool { return true }
func (m *mockToken) Error() error                   { return m.err }

// publishedMessage captures one mock Publish call.
type publishedMessage struct {
	Topic    string
	QoS      byte
	Retained bool
	Payload  []byte
}

// mockClient is a test double for Paho. It records every Publish, honours
// IsConnected, and can be pre-programmed to fail the next operation.
type mockClient struct {
	mu        sync.Mutex
	connected atomic.Bool
	connectFn func() error
	messages  []publishedMessage
}

func (m *mockClient) Connect() Token {
	err := (error)(nil)
	if m.connectFn != nil {
		err = m.connectFn()
	}
	if err == nil {
		m.connected.Store(true)
	}
	return &mockToken{err: err}
}
func (m *mockClient) Disconnect(uint)   { m.connected.Store(false) }
func (m *mockClient) IsConnected() bool { return m.connected.Load() }
func (m *mockClient) Publish(topic string, qos byte, retained bool, payload interface{}) Token {
	m.mu.Lock()
	defer m.mu.Unlock()
	var body []byte
	switch v := payload.(type) {
	case []byte:
		body = v
	case string:
		body = []byte(v)
	default:
		body, _ = json.Marshal(v)
	}
	m.messages = append(m.messages, publishedMessage{
		Topic: topic, QoS: qos, Retained: retained, Payload: body,
	})
	return &mockToken{}
}

func (m *mockClient) Messages() []publishedMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]publishedMessage, len(m.messages))
	copy(out, m.messages)
	return out
}

// factoryFor returns a Factory that always yields the supplied mock and
// registers its OnConnect handler for later invocation in test.
func factoryFor(mc *mockClient, onConnect *func(paho.Client)) Factory {
	return func(opts *paho.ClientOptions) Client {
		if onConnect != nil {
			*onConnect = opts.OnConnect
		}
		return mc
	}
}

// waitFor polls a predicate until deadline elapses or it returns true.
func waitFor(t *testing.T, d time.Duration, fn func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not satisfied within %s", d)
}

func TestBridge_DisabledIsNoOp(t *testing.T) {
	b := New(config.MQTTConfig{Enabled: false})
	if b.Enabled() {
		t.Fatal("disabled bridge reports Enabled=true")
	}
	// All the public methods must be safe on a no-op bridge.
	b.PublishEvent("anything", map[string]int{"x": 1})
	b.PublishToolLast("rfid_read", nil)
	b.PublishAuditCritical(nil)
	if err := b.Connect(); err != nil {
		t.Fatalf("no-op Connect returned %v", err)
	}
	b.Close()
}

func TestBridge_ConnectPublishesOnlineRetained(t *testing.T) {
	mc := &mockClient{}
	var onConn func(paho.Client)
	b := NewWithFactory(config.MQTTConfig{
		Enabled:  true,
		Broker:   "tcp://mock:1883",
		ClientID: "pz",
		BasePath: "pz",
	}, factoryFor(mc, &onConn))
	if err := b.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	// Simulate the broker telling Paho "you're online".
	if onConn != nil {
		onConn(nil)
	}
	waitFor(t, time.Second, func() bool {
		for _, m := range mc.Messages() {
			if m.Topic == "pz/state/online" && m.Retained && string(m.Payload) == "true" {
				return true
			}
		}
		return false
	})
}

func TestBridge_PublishEventTopicAndPayload(t *testing.T) {
	mc := &mockClient{}
	mc.connected.Store(true) // short-circuit the "connected?" guard
	b := NewWithFactory(config.MQTTConfig{Enabled: true, Broker: "tcp://mock:1883", BasePath: "pz"},
		factoryFor(mc, nil))
	b.PublishEvent("tool_finished", map[string]any{"tool": "rfid_read", "ok": true})
	waitFor(t, time.Second, func() bool {
		for _, m := range mc.Messages() {
			if m.Topic == "pz/events/tool_finished" {
				var decoded map[string]any
				if err := json.Unmarshal(m.Payload, &decoded); err != nil {
					return false
				}
				return decoded["tool"] == "rfid_read"
			}
		}
		return false
	})
}

func TestBridge_PublishToolLastIsRetained(t *testing.T) {
	mc := &mockClient{}
	mc.connected.Store(true)
	b := NewWithFactory(config.MQTTConfig{Enabled: true, Broker: "tcp://mock:1883", BasePath: "pz"},
		factoryFor(mc, nil))
	b.PublishToolLast("nfc_read", map[string]string{"uid": "DEADBEEF"})
	waitFor(t, time.Second, func() bool {
		for _, m := range mc.Messages() {
			if m.Topic == "pz/tools/nfc_read/last" && m.Retained {
				return true
			}
		}
		return false
	})
}

func TestBridge_SanitizeWildcards(t *testing.T) {
	mc := &mockClient{}
	mc.connected.Store(true)
	b := NewWithFactory(config.MQTTConfig{Enabled: true, Broker: "tcp://mock:1883", BasePath: "pz"},
		factoryFor(mc, nil))
	b.PublishEvent("risk/critical", nil)
	waitFor(t, time.Second, func() bool {
		for _, m := range mc.Messages() {
			if m.Topic == "pz/events/risk_critical" {
				return true
			}
		}
		return false
	})
}

func TestBridge_DropsWhenDisconnected(t *testing.T) {
	mc := &mockClient{} // connected == false
	b := NewWithFactory(config.MQTTConfig{Enabled: true, Broker: "tcp://mock:1883", BasePath: "pz"},
		factoryFor(mc, nil))
	b.PublishEvent("tool_finished", map[string]int{"x": 1})
	time.Sleep(50 * time.Millisecond)
	if len(mc.Messages()) != 0 {
		t.Fatalf("expected 0 messages while disconnected, got %d", len(mc.Messages()))
	}
}

func TestBridge_ConnectFailureReturnsError(t *testing.T) {
	mc := &mockClient{connectFn: func() error { return errors.New("dial fail") }}
	b := NewWithFactory(config.MQTTConfig{Enabled: true, Broker: "tcp://mock:1883"},
		factoryFor(mc, nil))
	err := b.Connect()
	if err == nil || err.Error() != "dial fail" {
		t.Fatalf("expected dial fail, got %v", err)
	}
	if got := b.LastError(); got == nil {
		t.Fatalf("expected LastError set")
	}
}

func TestBridge_CloseFlipsOnlineFalse(t *testing.T) {
	mc := &mockClient{}
	mc.connected.Store(true)
	b := NewWithFactory(config.MQTTConfig{Enabled: true, Broker: "tcp://mock:1883", BasePath: "pz"},
		factoryFor(mc, nil))
	b.Close()
	found := false
	for _, m := range mc.Messages() {
		if m.Topic == "pz/state/online" && string(m.Payload) == "false" && m.Retained {
			found = true
		}
	}
	if !found {
		t.Fatal("expected retained pz/state/online=false on Close")
	}
	if mc.IsConnected() {
		t.Fatal("expected disconnect on Close")
	}
}

func TestBridge_DefaultBasePath(t *testing.T) {
	mc := &mockClient{}
	mc.connected.Store(true)
	b := NewWithFactory(config.MQTTConfig{Enabled: true, Broker: "tcp://mock:1883"}, factoryFor(mc, nil))
	if b.BasePath() != "promptzero" {
		t.Fatalf("default base: %s", b.BasePath())
	}
	b.PublishAuditCritical(map[string]string{"tool": "x"})
	waitFor(t, time.Second, func() bool {
		for _, m := range mc.Messages() {
			if m.Topic == "promptzero/audit/critical" {
				return true
			}
		}
		return false
	})
}
