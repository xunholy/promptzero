// redis.go — host-side Redis RESP protocol decoder Spec. Wraps
// the internal/redis walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/redis"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(redisDecodeSpec)
}

var redisDecodeSpec = Spec{
	Name: "redis_decode",
	Description: "Decode a Redis RESP (REdis Serialization Protocol) v2 + v3 " +
		"message per the Redis documentation. TCP/6379 default; TCP/6380 " +
		"+ TCP/6381 (Sentinel); TCP/16379 + TCP/26379 (Cluster bus). The " +
		"third-largest open-source database pentest target after MySQL + " +
		"PostgreSQL — every modern web-app stack uses Redis for caching " +
		"/ sessions / queues / pub-sub; deployed everywhere from cloud-" +
		"managed Redis (AWS ElastiCache / MemoryDB / Google Cloud " +
		"Memorystore / Azure Cache / Upstash / Redis Enterprise Cloud) " +
		"to bare-metal to containerized side-cars. The canonical " +
		"\"exposed-to-the-internet without auth\" pentest target — " +
		"default deployments have NO authentication (requirepass unset; " +
		"protected-mode disabled + bound to 0.0.0.0 = unauthenticated " +
		"Redis exposed; Shodan finds 100,000+ unauthenticated instances " +
		"globally) AND multiple RCE primitives even after auth (**CONFIG " +
		"SET dir + dbfilename + SAVE = SSH authorized_keys / cron / " +
		"webshell write**; **MODULE LOAD = direct native-code RCE**; " +
		"**SCRIPT/EVAL = Lua sandbox escape CVE-2022-0543 Debian Redis**; " +
		"**SLAVEOF/REPLICAOF = replication-RCE via attacker-crafted RDB " +
		"with malicious module**). The wire format leaks: **AUTH with " +
		"cleartext password** (`*2\\r\\n$4\\r\\nAUTH\\r\\n$N\\r\\n<password>" +
		"\\r\\n` — password sent in plain text on TCP/6379; Redis 6+ " +
		"supports TLS but opt-in; decoder surfaces password_bytes LENGTH " +
		"only, privacy-preserving); **HELLO with embedded AUTH** (RESP3 " +
		"protocol negotiation with optional inline `AUTH <user> " +
		"<password>` parameters); **dangerous-command detection** (CONFIG " +
		"/ DEBUG / MODULE / SCRIPT / EVAL / SLAVEOF / REPLICAOF / " +
		"SHUTDOWN / FLUSHDB / FLUSHALL / CLIENT KILL flagged with attack-" +
		"vector classification); **brute-force feedback** (-NOAUTH = " +
		"server requires AUTH, pre-auth signal; -WRONGPASS = canonical " +
		"wrong-password response — password-spray tools consume directly; " +
		"-PERMISSION = ACL denied). Decodes:\n\n" +
		"- **5-entry RESP2 type discrimination** by first byte: `+` " +
		"Simple String / `-` Error / `:` Integer / `$` Bulk String / " +
		"`*` Array.\n" +
		"- **8-entry RESP3 type discrimination**: `%` Map / `~` Set / " +
		"`,` Double / `(` Big Number / `#` Boolean / `_` Null / `=` " +
		"Verbatim String / `>` Push.\n" +
		"- **CRLF frame walker** — each value is `\\r\\n`-terminated; " +
		"Bulk Strings have a `$N\\r\\n<N bytes>\\r\\n` length-prefixed " +
		"form (N=-1 indicates null); Arrays have a `*N\\r\\n` count-" +
		"prefixed form (N=-1 indicates null array).\n" +
		"- **Top-level Array of Bulk Strings detection** — the canonical " +
		"client→server command shape. Surfaces `command` (uppercased) + " +
		"`argument_count` + `arguments` (up to 16 elements, each " +
		"truncated to 256 bytes for surfacing).\n" +
		"- **Command classification + dangerous-command flagging** " +
		"against a 13-entry table: AUTH (cleartext password!) / HELLO " +
		"(RESP3 with inline AUTH) / CONFIG (CONFIG SET = RCE primitive " +
		"when targeting dir/dbfilename) / DEBUG (SLEEP DoS, OBJECT leak, " +
		"RELOAD) / MODULE (MODULE LOAD = direct native-code RCE) / " +
		"SCRIPT (Lua scripting prep) / EVAL + EVALSHA (Lua execution — " +
		"CVE-2022-0543 sandbox escape) / SLAVEOF + REPLICAOF " +
		"(replication-based RCE) / SHUTDOWN / FLUSHDB + FLUSHALL (data " +
		"destruction) / CLIENT KILL.\n" +
		"- **AUTH command password-length surfacing** — for `AUTH " +
		"<password>` (one-arg) surfaces `password_bytes`; for `AUTH " +
		"<user> <password>` (two-arg, Redis 6 ACL) surfaces both " +
		"`auth_username` cleartext and `password_bytes` length.\n" +
		"- **HELLO inline-AUTH detection** — scans HELLO arguments for " +
		"an `AUTH` keyword followed by user + password; surfaces the " +
		"same fields as AUTH.\n" +
		"- **Error response 11-entry classification table**: NOAUTH " +
		"(pre-auth signal!) / WRONGPASS (canonical brute-force " +
		"feedback!) / PERMISSION (ACL denied) / MOVED + ASK (Cluster " +
		"redirection) / LOADING (server warming) / BUSY (script " +
		"execution) / MASTERDOWN (Sentinel failover) / CLUSTERDOWN " +
		"(Cluster slot coverage incomplete) / READONLY (write to read-" +
		"only replica) / ERR (generic).\n\n" +
		"Pure offline parser — operators paste Redis RESP bytes (the " +
		"TCP-segment payload as hex; default TCP/6379) from a `tcpdump " +
		"-X port 6379` line or a Wireshark Redis dissector view and get " +
		"the documented per-command + per-error breakdown.\n\n" +
		"Out of scope (deferred): RDB persistence file format (binary " +
		"snapshot Redis writes via BGSAVE / SAVE — separate dissector); " +
		"AOF (Append-Only File) format (on-disk command write-ahead " +
		"log); Cluster slot map binary encoding (CLUSTER SLOTS / CLUSTER " +
		"SHARDS response format + gossip protocol on TCP/16379+); module " +
		"command IDLs (RediSearch FT.* / RedisJSON JSON.* / RedisGraph " +
		"GRAPH.* / RedisTimeSeries TS.* / RedisBloom BF.* — module-" +
		"specific argument semantics surfaced as ordinary commands); " +
		"sub-array deep recursion (top-level Array parsed; nested " +
		"Arrays inside arguments parsed only enough to find boundaries); " +
		"TLS handshake (Redis 6+ supports TLS — handle TLS strip first); " +
		"RESP3 attribute prefix (`|N\\r\\n`) detected but contents not " +
		"surfaced; client tracking push invalidation messages; full key-" +
		"value content (command shape + key surfaced; value arguments " +
		"surfaced as length only for SET / SETEX / MSET / HSET / etc.).\n\n" +
		"Source: docs/catalog/gap-analysis.md (database-protocol " +
		"foundational decoder — canonical Redis pentest dissector for " +
		"AUTH cleartext capture + dangerous-command detection + brute-" +
		"force feedback + RCE primitive flagging; canonical decode for " +
		"every Redis instance in cloud + on-prem + container deployments; " +
		"common in DEF CON + Black Hat + HITB + OffSec engagements + " +
		"every redis-cli / nmap redis-* NSE / metasploit redis_login-" +
		"driven Redis attack workflow). Wrap-vs-native: native — RESP is " +
		"publicly documented; simple text protocol with five primary " +
		"types + eight RESP3 additions; CRLF-walker with length-prefixed " +
		"Bulk Strings + count-prefixed Arrays; no third-party Redis " +
		"library; no crypto at the parse layer; password contents NEVER " +
		"decoded (password_bytes length only — privacy-preserving while " +
		"flagging the AUTH cleartext exposure).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Redis RESP message bytes as hex (the TCP-segment payload; default TCP/6379). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   redisDecodeHandler,
}

func redisDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("redis_decode: 'hex' is required")
	}
	res, err := redis.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("redis_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
