// estransport.go — host-side Elasticsearch transport protocol decoder Spec.
// Wraps the internal/estransport walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/estransport"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(esTransportDecodeSpec)
}

var esTransportDecodeSpec = Spec{
	Name: "es_transport_decode",
	Description: "Decode an Elasticsearch internal transport protocol frame " +
		"(TCP/9300 — inter-node communication). NOT the HTTP REST API " +
		"(TCP/9200). The transport protocol is the binary protocol cluster " +
		"nodes use to exchange cluster state, shard assignments, search " +
		"results, and index operations. Compatible with Elasticsearch 7.x " +
		"and 8.x (ES 7.x+ framing: total_size 4 BE + \"ES\" magic marker + " +
		"VInt header_size + request_id 8 BE + status byte + VInt transport " +
		"version + action name string).\n\n" +
		"Security relevance — TCP/9300 is a high-value unauthenticated " +
		"target in default Elasticsearch configurations: " +
		"**no authentication required** in default configs (pre-8.x without " +
		"xpack.security enabled); any node speaking the transport protocol " +
		"can join the cluster and gain full read/write access to all indices; " +
		"transport traffic contains index data, search queries, cluster state " +
		"updates, and shard routing decisions; action names reveal internal " +
		"operations and the full API surface; misconfigured ES clusters are " +
		"frequently internet-exposed on TCP/9300 — Shodan regularly finds " +
		"them; joining gives immediate access to all stored documents " +
		"without further authentication. The transport protocol is " +
		"**distinct from the REST API** (TCP/9200) — scanning TCP/9300 " +
		"reveals the cluster transport surface.\n\n" +
		"Decodes:\n\n" +
		"- **\"ES\" magic marker detection** (0x45 0x53) — `has_es_marker` " +
		"boolean; rejects non-ES-transport frames immediately.\n" +
		"- **Frame size** — `message_size` (4 BE prefix before the ES " +
		"marker).\n" +
		"- **Request ID** — `request_id` (8-byte BE long; monotonically " +
		"increasing per connection; correlates requests with responses).\n" +
		"- **Status flags** from the 1-byte status field: " +
		"`is_request` (bit 0x01) / `is_response` (bit 0x02) / " +
		"`is_error` (bit 0x04) / `is_compressed` (bit 0x08) / " +
		"`is_handshake` (bit 0x10).\n" +
		"- **Transport version** — `transport_version` (VInt encoded; " +
		"internal protocol versioning, not the ES release version).\n" +
		"- **Action name** — `action_name` (length-prefixed string; " +
		"identifies the operation being performed). Examples: " +
		"\"internal:cluster/state\" (cluster state sync), " +
		"\"internal:cluster/nodes\" (node discovery), " +
		"\"indices:data/read/search\" (search request), " +
		"\"indices:data/write/index\" (document indexing), " +
		"\"indices:admin/create\" (index creation), " +
		"\"cluster:monitor/nodes/info\" (node info query).\n" +
		"- **Action classification**: " +
		"`is_cluster_state` (cluster state / node operations), " +
		"`is_search` (search requests), " +
		"`is_index` (index write / admin operations), " +
		"`is_handshake_frame` (transport handshake), " +
		"`is_internal_action` (\"internal:\" prefix actions).\n\n" +
		"Pure offline parser — paste Elasticsearch transport bytes " +
		"(TCP-segment payload hex; TCP/9300) from tcpdump / Wireshark " +
		"Elasticsearch dissector and get a per-frame breakdown.\n\n" +
		"Out of scope: ES 6.x and earlier transport framing variants; " +
		"message body / response payload parsing; TLS transport layer " +
		"(ES 8.x xpack.security.transport.ssl — handle TLS strip first); " +
		"cluster join protocol beyond handshake detection; credential " +
		"extraction (ES transport does not carry credentials in the frame " +
		"header in default configuration).\n\n" +
		"Source: gap analysis (inter-node cluster communication protocol " +
		"decoder — TCP/9300 unauthenticated transport surface; pairs with " +
		"ldap_decode / redis_decode / mongodb_decode for the full " +
		"unauthenticated-database pentest surface). Wrap-vs-native: " +
		"native — ES transport framing is a deterministic binary format " +
		"with a fixed \"ES\" magic marker, BE integers, VInt fields, and " +
		"length-prefixed strings; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Elasticsearch transport protocol frame bytes as hex (the TCP-segment payload; TCP/9300 inter-node transport). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   esTransportDecodeHandler,
}

func esTransportDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("es_transport_decode: 'hex' is required")
	}
	res, err := estransport.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("es_transport_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
