// memcached.go — host-side Memcached binary-protocol decoder Spec.
// Wraps the internal/memcached walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/memcached"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(memcachedDecodeSpec)
}

var memcachedDecodeSpec = Spec{
	Name: "memcached_decode",
	Description: "Decode a Memcached binary-protocol message per the Memcached " +
		"binary protocol specification. TCP/11211 (default). Compatible " +
		"with Memcached, Amazon ElastiCache (Memcached-compatible), " +
		"Google Cloud Memorystore, Couchbase (data port). High-value " +
		"cache target — caches session tokens, user data, API " +
		"responses. Default Memcached ships with NO authentication and " +
		"binds to all interfaces; Shodan finds tens of thousands of " +
		"exposed instances on TCP/11211. Weaponised for massive DDoS " +
		"reflection/amplification (CVE-2018-1000115, 51000x " +
		"amplification via UDP).\n\n" +
		"The wire format leaks: **key names in cleartext** (every " +
		"GET/SET/DELETE/INCR/DECR carries the cache key — keys often " +
		"encode application structure e.g. 'session:abc123', " +
		"'user:42:profile', 'api:rate:10.0.0.1'); **cached values in " +
		"cleartext** (SET/ADD/REPLACE carry the value payload — often " +
		"serialised user sessions, API tokens, application objects); " +
		"**SASL authentication** (when configured — Couchbase, " +
		"ElastiCache with auth — SASL PLAIN = cleartext " +
		"\\0<username>\\0<password>; decoder surfaces auth_bytes " +
		"LENGTH only, privacy-preserving); **stats command exposure** " +
		"(STAT opcode 0x10 returns PID, version, uptime, connections, " +
		"evictions, memory — canonical version fingerprint + resource " +
		"profiling).\n\n" +
		"Decodes:\n\n" +
		"- **24-byte header walker**: magic (0x80 request / 0x81 " +
		"response) + opcode + key_length (2 BE) + extras_length + " +
		"data_type + status (response) / vbucket_id (request) + " +
		"total_body_length (4 BE) + opaque (4 BE) + CAS (8 BE).\n" +
		"- **35-entry opcode name table**: Get (0x00) through SASL " +
		"Step (0x22) including quiet (Q) variants.\n" +
		"- **Key extraction**: cache key from body (key_length bytes " +
		"after extras).\n" +
		"- **Value length computation**: total_body - key_length - " +
		"extras_length.\n" +
		"- **Response status decoder**: 15-entry status table (No " +
		"error through Temporary failure).\n" +
		"- **SET extras walker**: flags (4 BE) + expiration (4 BE).\n" +
		"- **INCR/DECR extras walker**: delta (8 BE) + initial (8 " +
		"BE) + expiration (4 BE).\n" +
		"- **SASL detection**: flags SASL Auth (0x21) / SASL Step " +
		"(0x22) with auth_bytes length.\n" +
		"- **Operation classification**: data_operation / " +
		"admin_operation / version_probe / sasl_auth.\n\n" +
		"Pure offline parser — paste Memcached bytes (TCP-segment " +
		"payload hex; default TCP/11211) from tcpdump / Wireshark " +
		"Memcached dissector and get per-message breakdown.\n\n" +
		"Out of scope: Memcached text protocol ('get key\\r\\n' text " +
		"format — binary protocol only); value deserialization (JSON, " +
		"msgpack, application-specific — surfaced as value_length " +
		"only); UDP Memcached (8-byte datagram header); TLS " +
		"(Memcached 1.5.13+ — strip TLS first); proxy protocol " +
		"headers; credential extraction (auth_bytes LENGTH only — " +
		"NEVER surfaces actual credentials or cached values).\n\n" +
		"Source: gap analysis (enterprise caching backbone — " +
		"canonical Memcached pentest dissector for key-name " +
		"application structure disclosure + SASL auth detection + " +
		"stats version fingerprint + DDoS amplification context; " +
		"pairs with redis_decode for the in-memory data store " +
		"surface). Wrap-vs-native: native — Memcached binary " +
		"protocol is publicly documented; 24-byte fixed header; " +
		"body is extras + key + value at known offsets; no crypto " +
		"at the parse layer; SASL payload NEVER decoded (length " +
		"only).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Memcached binary-protocol message bytes as hex (the TCP-segment payload; default TCP/11211). Starts with magic byte 0x80 (request) or 0x81 (response). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   memcachedDecodeHandler,
}

func memcachedDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("memcached_decode: 'hex' is required")
	}
	res, err := memcached.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("memcached_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
