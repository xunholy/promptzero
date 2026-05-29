// Package redis decodes Redis RESP (REdis Serialization Protocol)
// v2 + v3 messages per the Redis documentation. Runs on TCP/6379
// (default Redis), TCP/6380 + TCP/6381 (Sentinel), TCP/16379 +
// TCP/26379 (Cluster bus). The third-largest open-source database
// pentest target after MySQL + PostgreSQL — every modern web-app
// stack uses Redis for caching / sessions / queues / pub-sub.
// Deployed everywhere from cloud-managed Redis (AWS ElastiCache /
// MemoryDB / Google Cloud Memorystore / Azure Cache / Upstash /
// Redis Enterprise Cloud) to bare-metal to containerized side-
// cars.
//
// Operationally, Redis is the **canonical "exposed-to-the-
// internet without auth" pentest target** because:
//
//   - **Default deployments have NO authentication** —
//     `requirepass` is unset by default; the only protection
//     is the `protected-mode` flag (introduced in 3.2) which
//     refuses connections from non-localhost when no password
//     is set. Disabling protected-mode + binding to 0.0.0.0 =
//     unauthenticated Redis exposed to the internet. Shodan
//     finds 100,000+ unauthenticated Redis instances on
//     TCP/6379 globally.
//
//   - **Multiple RCE primitives** — even when AUTH is required,
//     successful authentication often grants enough power to
//     achieve RCE:
//
//   - `CONFIG SET dir /home/<user>/.ssh` + `CONFIG SET
//     dbfilename authorized_keys` + `SET <random> "ssh-rsa
//     ..."` + `SAVE` — writes an SSH authorized_keys file
//     via Redis persistence. The canonical Redis-to-shell.
//
//   - `MODULE LOAD /path/to/evil.so` — load arbitrary
//     native code (Redis 4.0+) as a module. Direct RCE.
//
//   - `SCRIPT LOAD` / `EVAL` — Lua scripting; CVE-2022-0543
//     (Debian Redis Lua sandbox escape) allowed RCE via
//     `package.loadlib`.
//
//   - `SLAVEOF` / `REPLICAOF` an attacker-controlled host
//     coerces the victim into restoring an attacker-crafted
//     RDB file (which can contain a malicious module).
//
//   - **Cleartext password on the wire** — `AUTH <password>`
//     sends the password as a Bulk String over TCP/6379 in
//     cleartext (Redis 6+ supports TLS but it's opt-in and
//     uncommon in legacy deployments). The decoder surfaces
//     the AUTH command but reports `password_bytes` LENGTH
//     only (privacy-preserving — never the password
//     itself).
//
//   - **Brute-force-friendly auth** — when `requirepass` is
//     set, AUTH responses are `+OK\r\n` for success or
//     `-WRONGPASS invalid username-password pair\r\n` for
//     failure. Default Redis has no rate limiting (Redis
//     6.2+ adds optional ACL-based limits).
//
// The wire format leaks:
//
//   - **AUTH with cleartext password** — `*2\r\n$4\r\nAUTH\r\n
//     $N\r\n<password>\r\n`. Surfaces `is_auth_command`
//     boolean + `password_bytes` length only.
//   - **HELLO with embedded AUTH** — `HELLO 3 AUTH <user>
//     <password> SETNAME <name>` — RESP3 protocol
//     negotiation with optional inline credentials.
//   - **Dangerous command detection** — flags CONFIG / DEBUG
//     / MODULE / SCRIPT / EVAL / SLAVEOF / REPLICAOF /
//     SHUTDOWN / FLUSHDB / FLUSHALL / CLIENT KILL with the
//     attack-vector classification.
//   - **Brute-force feedback via error responses** —
//     `-NOAUTH` (server requires AUTH — pre-auth signal),
//     `-WRONGPASS` (canonical wrong-password — password-
//     spray feedback), `-PERMISSION` (ACL denied),
//     `-MOVED` / `-ASK` (Cluster slot redirection),
//     `-LOADING` (server warming), `-BUSY` (script running).
//
// Wrap-vs-native judgement
//
//	Native. RESP is publicly documented; it's a simple text
//	protocol with five primary types (Simple String / Error /
//	Integer / Bulk String / Array) plus eight RESP3 additions.
//	Frame parsing is a CRLF-walker with length-prefixed bulk
//	strings + count-prefixed arrays. RDB persistence format,
//	AOF format, Cluster slot map, module command IDLs, and
//	RediSearch / RedisJSON / RedisTimeSeries module-specific
//	command semantics are out of scope.
//
// What this package covers
//
//   - **5-entry RESP2 type discrimination** by first byte:
//     `+` Simple String / `-` Error / `:` Integer / `$` Bulk
//     String / `*` Array.
//
//   - **8-entry RESP3 type discrimination** (in addition to
//     RESP2): `%` Map / `~` Set / `,` Double / `(` Big Number
//     / `#` Boolean / `_` Null / `=` Verbatim String / `>`
//     Push.
//
//   - **CRLF frame walker** — each value is `\r\n`-terminated;
//     Bulk Strings have a `$N\r\n<N bytes>\r\n` length-
//     prefixed form (N=-1 indicates null); Arrays have a
//     `*N\r\n` count-prefixed form (N=-1 indicates null
//     array).
//
//   - **Top-level Array of Bulk Strings detection** — the
//     canonical client→server command shape. Surfaces
//     `command` (first element, uppercased) +
//     `argument_count` + `arguments` (subsequent elements,
//     up to 16 — each truncated to 256 bytes for surfacing).
//
//   - **Command classification + dangerous-command flagging**
//     against a 13-entry table: AUTH / HELLO / CONFIG /
//     DEBUG / MODULE / SCRIPT / EVAL / EVALSHA / SLAVEOF /
//     REPLICAOF / SHUTDOWN / FLUSHDB / FLUSHALL / CLIENT.
//
//   - **AUTH command password-length surfacing** — for
//     `AUTH <password>` (one-arg) surfaces `password_bytes`;
//     for `AUTH <user> <password>` (two-arg, Redis 6 ACL)
//     surfaces both `auth_username` cleartext and
//     `password_bytes` length.
//
//   - **HELLO inline-AUTH detection** — scans HELLO
//     arguments for an `AUTH` keyword followed by user +
//     password; surfaces the same fields as AUTH.
//
//   - **Error response classification** — for `-` Error
//     frames: NOAUTH (pre-auth signal!) / WRONGPASS
//     (canonical brute-force feedback!) / PERMISSION (ACL
//     denied) / MOVED + ASK (Cluster redirection) / LOADING
//     (server warming) / BUSY (script running) / MASTERDOWN
//
//   - CLUSTERDOWN (failover) / READONLY (replica write) /
//     ERR (generic).
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **RDB persistence file format** — the binary snapshot
//     Redis writes via `BGSAVE` / `SAVE`; separate dissector
//     concern.
//   - **AOF (Append-Only File) format** — the on-disk
//     command write-ahead log.
//   - **Cluster slot map binary encoding** —
//     `CLUSTER SLOTS` / `CLUSTER SHARDS` response format
//     and the gossip protocol on TCP/16379+.
//   - **Module command IDLs** — RediSearch (FT.*), RedisJSON
//     (JSON.*), RedisGraph (GRAPH.*), RedisTimeSeries (TS.*),
//     RedisBloom (BF.* / CF.* / TDIGEST.*) follow standard
//     RESP framing but their argument semantics are module-
//     specific; surfaced as ordinary commands.
//   - **Sub-array deep recursion** — top-level Array parsed;
//     nested Arrays inside arguments parsed only enough to
//     find boundaries.
//   - **TLS handshake** — Redis 6+ supports TLS; handle the
//     TLS strip first.
//   - **RESP3 attribute prefix** (`|N\r\n`) — detected but
//     contents not surfaced.
//   - **Client tracking** push invalidation messages.
//   - **Full key-value content** — surfaces command shape +
//     key argument; value arguments surfaced as length only
//     for SET / SETEX / MSET / HSET / etc.
package redis

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Result is the structured decode of a Redis RESP message.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	FrameType     string `json:"frame_type"`
	FrameTypeName string `json:"frame_type_name"`

	// Command-detection (top-level Array of Bulk Strings)
	IsCommand     bool     `json:"is_command"`
	Command       string   `json:"command,omitempty"`
	ArgumentCount int      `json:"argument_count,omitempty"`
	Arguments     []string `json:"arguments,omitempty"`

	// Command classification
	IsAuthCommand        bool   `json:"is_auth_command"`
	IsHelloCommand       bool   `json:"is_hello_command"`
	IsDangerousCommand   bool   `json:"is_dangerous_command"`
	DangerousCommandFlag string `json:"dangerous_command_flag,omitempty"`

	// AUTH command field surfacing
	AuthUsername  string `json:"auth_username,omitempty"`
	PasswordBytes int    `json:"password_bytes,omitempty"`

	// Error response classification
	IsError       bool   `json:"is_error"`
	ErrorText     string `json:"error_text,omitempty"`
	ErrorCategory string `json:"error_category,omitempty"`

	// Simple value surfacing
	SimpleString string `json:"simple_string,omitempty"`
	Integer      int64  `json:"integer,omitempty"`
}

// Decode parses a RESP message from a hex string.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if len(clean) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex (%d nibbles)", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("empty body")
	}

	r := &Result{TotalBytes: len(b)}
	r.FrameType = string(b[0:1])
	r.FrameTypeName = frameTypeName(b[0])

	switch b[0] {
	case '+':
		r.SimpleString, _ = readLine(b, 1)
	case '-':
		r.IsError = true
		r.ErrorText, _ = readLine(b, 1)
		r.ErrorCategory = errorCategory(r.ErrorText)
	case ':':
		s, _ := readLine(b, 1)
		v, _ := strconv.ParseInt(s, 10, 64)
		r.Integer = v
	case '*':
		decodeArray(r, b)
	}
	return r, nil
}

// decodeArray parses the top-level Array; if it's an Array of
// Bulk Strings, classifies it as a command.
func decodeArray(r *Result, b []byte) {
	countStr, off := readLine(b, 1)
	count, err := strconv.Atoi(countStr)
	if err != nil || count < 0 {
		return
	}
	if count == 0 {
		return
	}
	r.ArgumentCount = count - 1
	// Cap the preallocation hint to the remaining byte count. A RESP
	// array header can declare an astronomically large element count
	// (e.g. "*999999999\r\n"), and make([]string, 0, count) would OOM
	// before the self-limiting loop (bounded by off < len(b)) could
	// run. Each element consumes at least one byte, so the realised
	// count can never exceed the bytes available. Found by
	// FuzzHexDecoders.
	hint := count
	if hint > len(b) {
		hint = len(b)
	}
	args := make([]string, 0, hint)
	argLens := make([]int, 0, hint)
	allBulk := true
	for i := 0; i < count && off < len(b); i++ {
		if b[off] != '$' {
			allBulk = false
			break
		}
		lenStr, next := readLine(b, off+1)
		l, err := strconv.Atoi(lenStr)
		if err != nil {
			break
		}
		if l < 0 {
			args = append(args, "")
			argLens = append(argLens, 0)
			off = next
			continue
		}
		start := next
		end := start + l
		if end > len(b) {
			end = len(b)
		}
		args = append(args, string(b[start:end]))
		argLens = append(argLens, l)
		off = end + 2
	}
	if !allBulk || len(args) == 0 {
		return
	}
	r.IsCommand = true
	r.Command = strings.ToUpper(args[0])
	limit := len(args) - 1
	if limit > 16 {
		limit = 16
	}
	r.Arguments = make([]string, limit)
	for i := 0; i < limit; i++ {
		a := args[i+1]
		if len(a) > 256 {
			a = a[:256] + "..."
		}
		r.Arguments[i] = a
	}
	classifyCommand(r, args, argLens)
}

func classifyCommand(r *Result, args []string, argLens []int) {
	cmd := r.Command
	switch cmd {
	case "AUTH":
		r.IsAuthCommand = true
		r.IsDangerousCommand = true
		r.DangerousCommandFlag = "AUTH — password sent CLEARTEXT on the wire (Redis 6+ supports TLS but opt-in)"
		if len(args) == 2 {
			r.PasswordBytes = argLens[1]
		} else if len(args) >= 3 {
			r.AuthUsername = args[1]
			r.PasswordBytes = argLens[2]
		}
	case "HELLO":
		r.IsHelloCommand = true
		for i, a := range args {
			if strings.EqualFold(a, "AUTH") && i+2 < len(args) {
				r.IsAuthCommand = true
				r.AuthUsername = args[i+1]
				r.PasswordBytes = argLens[i+2]
				r.IsDangerousCommand = true
				r.DangerousCommandFlag = "HELLO with inline AUTH — password sent CLEARTEXT on the wire"
				break
			}
		}
	case "CONFIG":
		r.IsDangerousCommand = true
		if len(args) >= 2 && strings.EqualFold(args[1], "SET") {
			r.DangerousCommandFlag = "CONFIG SET — RCE primitive when targeting dir/dbfilename (write SSH authorized_keys, cron, webshell)"
		} else {
			r.DangerousCommandFlag = "CONFIG — server configuration access (CONFIG GET leaks requirepass/dir/dbfilename)"
		}
	case "DEBUG":
		r.IsDangerousCommand = true
		r.DangerousCommandFlag = "DEBUG — DoS (DEBUG SLEEP), internal-state leak (DEBUG OBJECT), or persistence reload"
	case "MODULE":
		r.IsDangerousCommand = true
		r.DangerousCommandFlag = "MODULE — MODULE LOAD = direct native-code RCE primitive"
	case "SCRIPT":
		r.IsDangerousCommand = true
		r.DangerousCommandFlag = "SCRIPT — Lua scripting prep; sandbox-escape vector historically (CVE-2022-0543)"
	case "EVAL", "EVALSHA":
		r.IsDangerousCommand = true
		r.DangerousCommandFlag = "EVAL/EVALSHA — Lua scripting execution; sandbox-escape vector historically (CVE-2022-0543 Debian Redis)"
	case "SLAVEOF", "REPLICAOF":
		r.IsDangerousCommand = true
		r.DangerousCommandFlag = "SLAVEOF/REPLICAOF — replication-based RCE primitive (slave-of-attacker can restore malicious RDB containing module)"
	case "SHUTDOWN":
		r.IsDangerousCommand = true
		r.DangerousCommandFlag = "SHUTDOWN — server stop (data loss if no SAVE)"
	case "FLUSHDB", "FLUSHALL":
		r.IsDangerousCommand = true
		r.DangerousCommandFlag = "FLUSH* — data destruction"
	case "CLIENT":
		if len(args) >= 2 && strings.EqualFold(args[1], "KILL") {
			r.IsDangerousCommand = true
			r.DangerousCommandFlag = "CLIENT KILL — disconnects other clients"
		}
	}
}

func frameTypeName(t byte) string {
	switch t {
	case '+':
		return "SimpleString"
	case '-':
		return "Error"
	case ':':
		return "Integer"
	case '$':
		return "BulkString"
	case '*':
		return "Array"
	case '%':
		return "Map (RESP3)"
	case '~':
		return "Set (RESP3)"
	case ',':
		return "Double (RESP3)"
	case '(':
		return "BigNumber (RESP3)"
	case '#':
		return "Boolean (RESP3)"
	case '_':
		return "Null (RESP3)"
	case '=':
		return "VerbatimString (RESP3)"
	case '>':
		return "Push (RESP3)"
	}
	return fmt.Sprintf("uncatalogued frame type 0x%02X", t)
}

func errorCategory(text string) string {
	switch {
	case strings.HasPrefix(text, "NOAUTH"):
		return "NOAUTH (server requires AUTH — pre-auth signal!)"
	case strings.HasPrefix(text, "WRONGPASS"):
		return "WRONGPASS (canonical brute-force feedback — wrong password)"
	case strings.HasPrefix(text, "PERMISSION"):
		return "PERMISSION (ACL denied)"
	case strings.HasPrefix(text, "MOVED"):
		return "MOVED (Cluster slot redirection)"
	case strings.HasPrefix(text, "ASK"):
		return "ASK (Cluster slot ASK redirection)"
	case strings.HasPrefix(text, "LOADING"):
		return "LOADING (server warming after restart)"
	case strings.HasPrefix(text, "BUSY"):
		return "BUSY (script execution in progress)"
	case strings.HasPrefix(text, "MASTERDOWN"):
		return "MASTERDOWN (Sentinel failover trigger)"
	case strings.HasPrefix(text, "CLUSTERDOWN"):
		return "CLUSTERDOWN (Cluster slot coverage incomplete)"
	case strings.HasPrefix(text, "READONLY"):
		return "READONLY (writing to read-only replica)"
	case strings.HasPrefix(text, "ERR"):
		return "ERR (generic server error)"
	}
	return "uncatalogued error"
}

func readLine(b []byte, off int) (string, int) {
	end := off
	for end+1 < len(b) && (b[end] != '\r' || b[end+1] != '\n') {
		end++
	}
	if end+1 >= len(b) {
		return string(b[off:end]), len(b)
	}
	return string(b[off:end]), end + 2
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
