// Package tools — security Specs (v0.5 Tier-1 MCP harvest).
//
// # hash_identify
//
// Heuristic hash-format detector: inspects length, character class, and
// structural prefixes to produce a ranked candidate list.  Pure offline;
// no network or external dependencies.  Source: reimplemented from public
// algorithm descriptions (name-that-hash, hashcat --example-hashes docs).
// License posture: clean-reimpl.
//
// # hash_crack_dictionary
//
// Offline dictionary attack.  Reads a wordlist line-by-line (bufio.Scanner;
// streaming — never fully in memory) and hashes each candidate with the
// requested algorithm.  Algorithms: MD5, SHA-1, SHA-256, SHA-512 (stdlib),
// NTLM (MD4 of UTF-16LE via golang.org/x/crypto/md4), bcrypt
// (golang.org/x/crypto/bcrypt).  Concurrent goroutine pool bounded by
// the workers parameter.  License posture: clean-reimpl.
//
// # port_scan_tcp
//
// Host-side pure-Go TCP connect scan.  No raw sockets; no root required.
// Distinct from wifi_port_scan (which runs on the ESP32/Marauder sidecar).
// Concurrency-capped worker pool; per-connection and wall-clock timeouts.
// License posture: clean-reimpl.
//
// # http_enum_common
//
// Wordlist-driven HTTP path enumeration.  Concurrent GET requests;
// configurable status-code filter; soft-404 canary detection; ships with a
// built-in ~500-entry CC0 wordlist (internal/wordlists/common.txt).
// License posture: clean-reimpl; embedded wordlist is CC0-1.0.
package tools

import (
	"bufio"
	"context"
	"crypto/md5"  //nolint:gosec // MD5 used for hash cracking, not security
	"crypto/sha1" //nolint:gosec // SHA-1 used for hash cracking, not security
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/md4" //nolint:staticcheck // NTLM (MD4 of UTF-16LE) is the explicit legacy-compat use case for hash_crack_dictionary; the security warning is acknowledged.

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/wordlists"
)

//nolint:gochecknoinits
func init() {
	Register(hashIdentifySpec)
	Register(hashCrackDictionarySpec)
	Register(portScanTCPSpec)
	Register(httpEnumCommonSpec)
}

// ─────────────────────────────────────────────────────────────────────────────
// hash_identify
// ─────────────────────────────────────────────────────────────────────────────

var hashIdentifySpec = Spec{
	Name: "hash_identify",
	Description: "Heuristic hash-format identification. Returns ranked candidates with confidence " +
		"(0.0–1.0). Pure offline; no network or hashcat dependency. Use before hash_crack_dictionary " +
		"to determine the algorithm. Supported families: MD5, NTLM, MD4 (32 hex), SHA-1 (40 hex), " +
		"SHA-256 (64 hex), SHA-512 (128 hex), bcrypt ($2a/$2b/$2y), md5crypt ($1$), sha256crypt ($5$), " +
		"sha512crypt ($6$), Argon2 ($argon2id/$argon2i/$argon2d), MySQL323 (16 hex), " +
		"MySQL4.1+ (* + 40 hex), LDAP ({SSHA}/{SHA}/{MD5}).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hash":{"type":"string","description":"The hash string to classify"}
		},
		"required":["hash"]
	}`),
	Required: []string{"hash"},
	Risk:     risk.Low,
	Group:    GroupSecurity,
	Handler:  hashIdentifyHandler,
}

// hashCandidate is one entry in the ranked output.
type hashCandidate struct {
	Name       string  `json:"name"`
	Mode       int     `json:"mode"`
	Confidence float64 `json:"confidence"`
}

// hashIdentifyResult is the JSON output of hash_identify.
type hashIdentifyResult struct {
	Candidates  []hashCandidate `json:"candidates"`
	InputLength int             `json:"input_length"`
}

var (
	reHexOnly  = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	reHexLower = regexp.MustCompile(`^[0-9a-f]+$`)
	reHexUpper = regexp.MustCompile(`^[0-9A-F]+$`)
)

func hashIdentifyHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	input := strings.TrimSpace(str(p, "hash"))
	if input == "" {
		return "", fmt.Errorf("hash_identify: 'hash' argument is empty")
	}

	// Strip user:hash colon-separated prefix if present.
	if idx := strings.LastIndex(input, ":"); idx != -1 {
		if candidate := input[idx+1:]; len(candidate) > 0 {
			input = candidate
		}
	}

	candidates := identifyHash(input)
	result := hashIdentifyResult{
		Candidates:  candidates,
		InputLength: len(input),
	}
	b, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// identifyHash returns ranked hash-format candidates for the given string.
func identifyHash(h string) []hashCandidate {
	// Structural-prefix rules (high confidence).
	switch {
	case strings.HasPrefix(h, "$2a$") || strings.HasPrefix(h, "$2b$") ||
		strings.HasPrefix(h, "$2y$") || strings.HasPrefix(h, "$2x$"):
		return []hashCandidate{{Name: "bcrypt", Mode: 3200, Confidence: 0.99}}

	case strings.HasPrefix(h, "$1$"):
		return []hashCandidate{{Name: "md5crypt", Mode: 500, Confidence: 0.99}}

	case strings.HasPrefix(h, "$5$"):
		return []hashCandidate{{Name: "sha256crypt", Mode: 7400, Confidence: 0.99}}

	case strings.HasPrefix(h, "$6$"):
		return []hashCandidate{{Name: "sha512crypt", Mode: 1800, Confidence: 0.99}}

	case strings.HasPrefix(h, "$argon2id$"):
		return []hashCandidate{{Name: "Argon2id", Mode: 35200, Confidence: 0.99}}

	case strings.HasPrefix(h, "$argon2i$"):
		return []hashCandidate{{Name: "Argon2i", Mode: 13400, Confidence: 0.99}}

	case strings.HasPrefix(h, "$argon2d$"):
		return []hashCandidate{{Name: "Argon2d", Mode: 35200, Confidence: 0.98}}

	case strings.HasPrefix(h, "{SSHA}"):
		return []hashCandidate{{Name: "LDAP SSHA", Mode: 111, Confidence: 0.99}}

	case strings.HasPrefix(h, "{SHA}"):
		return []hashCandidate{{Name: "LDAP SHA-1", Mode: 101, Confidence: 0.99}}

	case strings.HasPrefix(h, "{MD5}"):
		return []hashCandidate{{Name: "LDAP MD5", Mode: 1001, Confidence: 0.99}}

	case strings.HasPrefix(h, "*") && len(h) == 41 && reHexOnly.MatchString(h[1:]):
		return []hashCandidate{{Name: "MySQL4.1+", Mode: 300, Confidence: 0.99}}
	}

	hexLen := len(h)
	isHex := reHexOnly.MatchString(h)
	isLower := reHexLower.MatchString(h)
	isUpper := reHexUpper.MatchString(h)

	switch {
	case hexLen == 16 && isHex:
		return []hashCandidate{
			{Name: "MySQL323", Mode: 200, Confidence: 0.70},
			{Name: "DES (half-block)", Mode: 1500, Confidence: 0.20},
		}

	case hexLen == 32 && isHex:
		// MD5, NTLM, MD4 share 32-char hex output; use case to bias ordering.
		// NTLM is typically output in uppercase by tools; MD5 in lowercase.
		switch {
		case isUpper:
			return []hashCandidate{
				{Name: "NTLM", Mode: 1000, Confidence: 0.55},
				{Name: "MD5", Mode: 0, Confidence: 0.30},
				{Name: "MD4", Mode: 900, Confidence: 0.15},
			}
		case isLower:
			return []hashCandidate{
				{Name: "MD5", Mode: 0, Confidence: 0.55},
				{Name: "NTLM", Mode: 1000, Confidence: 0.30},
				{Name: "MD4", Mode: 900, Confidence: 0.15},
			}
		default:
			return []hashCandidate{
				{Name: "NTLM", Mode: 1000, Confidence: 0.45},
				{Name: "MD5", Mode: 0, Confidence: 0.40},
				{Name: "MD4", Mode: 900, Confidence: 0.15},
			}
		}

	case hexLen == 40 && isHex:
		return []hashCandidate{
			{Name: "SHA-1", Mode: 100, Confidence: 0.90},
			{Name: "SHA-1 (various modes)", Mode: 110, Confidence: 0.08},
		}

	case hexLen == 64 && isHex:
		return []hashCandidate{
			{Name: "SHA-256", Mode: 1400, Confidence: 0.95},
			{Name: "Blake2b-256", Mode: 600, Confidence: 0.04},
		}

	case hexLen == 128 && isHex:
		return []hashCandidate{
			{Name: "SHA-512", Mode: 1700, Confidence: 0.93},
			{Name: "Whirlpool", Mode: 6100, Confidence: 0.04},
			{Name: "SHA3-512", Mode: 17600, Confidence: 0.03},
		}

	default:
		return []hashCandidate{{Name: "unknown", Mode: -1, Confidence: 0.0}}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// hash_crack_dictionary
// ─────────────────────────────────────────────────────────────────────────────

var hashCrackDictionarySpec = Spec{
	Name: "hash_crack_dictionary",
	Description: "Offline dictionary attack against a hash corpus. " +
		"Pure-Go implementation (MD5, SHA-1, SHA-256, SHA-512, NTLM, bcrypt). " +
		"No GPU, no rules engine. Reads the wordlist as a stream (memory-efficient " +
		"for large files such as rockyou.txt). Use hash_identify first to determine " +
		"the algorithm. Supported wordlists: operator-provided file path, or " +
		"'promptzero://wordlists/passwords.txt' for the built-in list.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hashes":{"type":"array","items":{"type":"string"},
				"description":"Hash strings to crack"},
			"algorithm":{"type":"string","enum":[
				"md5","sha1","sha256","sha512","ntlm","bcrypt"],
				"description":"Hash algorithm (output of hash_identify)"},
			"wordlist":{"type":"string",
				"description":"Path to a newline-separated wordlist file, or 'promptzero://wordlists/passwords.txt' for the built-in list"},
			"max_words":{"type":"integer","minimum":0,
				"description":"Cap on words tried; 0 = no cap"},
			"timeout_ms":{"type":"integer","minimum":1000,
				"description":"Wall-clock ceiling in ms (default 60000)"},
			"workers":{"type":"integer","minimum":1,
				"description":"Goroutine count (default NumCPU; capped at 4 for bcrypt)"}
		},
		"required":["hashes","algorithm","wordlist"]
	}`),
	Required: []string{"hashes", "algorithm", "wordlist"},
	Risk:     risk.Critical,
	Group:    GroupSecurity,
	Handler:  hashCrackDictionaryHandler,
}

// crackedEntry is one successfully-cracked hash in the output.
type crackedEntry struct {
	Hash      string `json:"hash"`
	Plaintext string `json:"plaintext"`
}

// hashCrackResult is the JSON output of hash_crack_dictionary.
type hashCrackResult struct {
	Cracked    []crackedEntry `json:"cracked"`
	Uncracked  []string       `json:"uncracked"`
	Algorithm  string         `json:"algorithm"`
	WordsTried int64          `json:"words_tried"`
	DurationMS int64          `json:"duration_ms"`
	Wordlist   string         `json:"wordlist"`
}

func hashCrackDictionaryHandler(ctx context.Context, _ *Deps, p map[string]any) (string, error) {
	start := time.Now()

	// --- Parse arguments ---
	hashesRaw, _ := p["hashes"].([]any)
	if len(hashesRaw) == 0 {
		return "", fmt.Errorf("hash_crack_dictionary: 'hashes' must be a non-empty array")
	}
	// Build two slices: origHashes (original casing) and lowerHashes (normalised).
	var origHashes []string
	var lowerHashes []string
	for _, v := range hashesRaw {
		if s, ok := v.(string); ok {
			s = strings.TrimSpace(s)
			if s != "" {
				origHashes = append(origHashes, s)
				lowerHashes = append(lowerHashes, strings.ToLower(s))
			}
		}
	}
	if len(origHashes) == 0 {
		return "", fmt.Errorf("hash_crack_dictionary: no valid hash strings provided")
	}

	algo := strings.ToLower(strings.TrimSpace(str(p, "algorithm")))
	if !isSupportedAlgo(algo) {
		return "", fmt.Errorf("hash_crack_dictionary: unsupported algorithm %q; supported: md5 sha1 sha256 sha512 ntlm bcrypt", algo)
	}

	wordlistPath := strings.TrimSpace(str(p, "wordlist"))
	if wordlistPath == "" {
		return "", fmt.Errorf("hash_crack_dictionary: 'wordlist' is required")
	}

	maxWords := intOr(p, "max_words", 0)
	timeoutMS := intOr(p, "timeout_ms", 60000)
	workers := intOr(p, "workers", runtime.NumCPU())
	if algo == "bcrypt" && workers > 4 {
		workers = 4 // bcrypt is slow; cap parallelism to avoid CPU saturation
	}
	if workers < 1 {
		workers = 1
	}

	// --- Open wordlist ---
	var wordReader io.ReadCloser
	if strings.HasPrefix(wordlistPath, "promptzero://wordlists/") {
		name := strings.TrimPrefix(wordlistPath, "promptzero://wordlists/")
		content, err := builtinWordlist(name)
		if err != nil {
			return "", fmt.Errorf("hash_crack_dictionary: %w", err)
		}
		wordReader = io.NopCloser(strings.NewReader(content))
	} else {
		f, err := os.Open(wordlistPath) //nolint:gosec // operator-controlled path
		if err != nil {
			return "", fmt.Errorf("hash_crack_dictionary: open wordlist: %w", err)
		}
		wordReader = f
	}
	defer wordReader.Close()

	// --- Setup context with timeout ---
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMS)*time.Millisecond)
	defer cancel()

	// --- Build target map: lowerHash → originalHash ---
	// For bcrypt the original casing is required because the hash encodes its
	// own cost and salt (bcrypt.CompareHashAndPassword needs the full original).
	targetMap := make(map[string]string, len(origHashes))
	for i, lh := range lowerHashes {
		targetMap[lh] = origHashes[i]
	}

	// --- Concurrent worker pool ---
	type crackResult struct {
		lowerHash string
		plaintext string
	}

	wordCh := make(chan string, workers*8)
	resultCh := make(chan crackResult, len(origHashes)+1)

	var remainMu sync.Mutex
	remaining := make(map[string]string, len(targetMap))
	for k, v := range targetMap {
		remaining[k] = v
	}

	var wordsTried int64
	var wordsMu sync.Mutex

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range wordCh {
				remainMu.Lock()
				allDone := len(remaining) == 0
				targets := make(map[string]string, len(remaining))
				for k, v := range remaining {
					targets[k] = v
				}
				remainMu.Unlock()

				if allDone {
					continue // drain the channel
				}

				wordsMu.Lock()
				wordsTried++
				wordsMu.Unlock()

				for lh, orig := range targets {
					if checkHash(algo, word, lh, orig) {
						resultCh <- crackResult{lowerHash: lh, plaintext: word}
						remainMu.Lock()
						delete(remaining, lh)
						remainMu.Unlock()
					}
				}
			}
		}()
	}

	// Producer — streams the wordlist without loading it into memory.
	go func() {
		scanner := bufio.NewScanner(wordReader)
		scanner.Buffer(make([]byte, 1<<20), 1<<20) // 1 MB line buffer
		var lineCount int
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				close(wordCh)
				return
			default:
			}
			word := scanner.Text()
			if word == "" || strings.HasPrefix(word, "#") {
				continue
			}
			remainMu.Lock()
			allDone := len(remaining) == 0
			remainMu.Unlock()
			if allDone {
				break
			}
			wordCh <- word
			lineCount++
			if maxWords > 0 && lineCount >= maxWords {
				break
			}
		}
		close(wordCh)
	}()

	wg.Wait()
	close(resultCh)

	// --- Collect results ---
	crackedMap := make(map[string]string, len(origHashes))
	for r := range resultCh {
		crackedMap[r.lowerHash] = r.plaintext
	}

	var cracked []crackedEntry
	var uncracked []string
	for i, lh := range lowerHashes {
		if pt, ok := crackedMap[lh]; ok {
			cracked = append(cracked, crackedEntry{Hash: origHashes[i], Plaintext: pt})
		} else {
			uncracked = append(uncracked, origHashes[i])
		}
	}
	if cracked == nil {
		cracked = []crackedEntry{}
	}
	if uncracked == nil {
		uncracked = []string{}
	}

	wordsMu.Lock()
	tried := wordsTried
	wordsMu.Unlock()

	res := hashCrackResult{
		Cracked:    cracked,
		Uncracked:  uncracked,
		Algorithm:  algo,
		WordsTried: tried,
		DurationMS: time.Since(start).Milliseconds(),
		Wordlist:   wordlistPath,
	}
	b, err := json.Marshal(res)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func isSupportedAlgo(algo string) bool {
	switch algo {
	case "md5", "sha1", "sha256", "sha512", "ntlm", "bcrypt":
		return true
	}
	return false
}

// checkHash returns true if word, when hashed under algo, matches the target.
// lowerHash is the lowercase-normalised target; origHash is the original form
// (required for bcrypt which self-encodes cost and salt).
func checkHash(algo, word, lowerHash, origHash string) bool {
	switch algo {
	case "md5":
		h := md5.Sum([]byte(word)) //nolint:gosec
		return hex.EncodeToString(h[:]) == lowerHash

	case "sha1":
		h := sha1.Sum([]byte(word)) //nolint:gosec
		return hex.EncodeToString(h[:]) == lowerHash

	case "sha256":
		h := sha256.Sum256([]byte(word))
		return hex.EncodeToString(h[:]) == lowerHash

	case "sha512":
		h := sha512.Sum512([]byte(word))
		return hex.EncodeToString(h[:]) == lowerHash

	case "ntlm":
		// NTLM = MD4(UTF-16LE(plaintext)) — Windows password hash.
		encoded := utf16.Encode([]rune(word))
		buf := make([]byte, len(encoded)*2)
		for i, r := range encoded {
			buf[i*2] = byte(r)
			buf[i*2+1] = byte(r >> 8)
		}
		h := md4.New()
		_, _ = h.Write(buf)
		return hex.EncodeToString(h.Sum(nil)) == lowerHash

	case "bcrypt":
		return bcrypt.CompareHashAndPassword([]byte(origHash), []byte(word)) == nil
	}
	return false
}

// builtinWordlist returns the raw embedded text of a named built-in wordlist.
func builtinWordlist(name string) (string, error) {
	switch name {
	case "common.txt":
		return wordlists.CommonRaw(), nil
	case "passwords.txt":
		return wordlists.PasswordsRaw(), nil
	}
	return "", fmt.Errorf("unknown built-in wordlist %q; available: common.txt, passwords.txt", name)
}

// ─────────────────────────────────────────────────────────────────────────────
// port_scan_tcp
// ─────────────────────────────────────────────────────────────────────────────

var portScanTCPSpec = Spec{
	Name: "port_scan_tcp",
	Description: "Pure-Go TCP connect scan from the operator's host. No raw sockets (no root needed). " +
		"Distinct from wifi_port_scan, which scans from the Marauder ESP32. " +
		"Use this for direct-network recon when the operator is on the same network as the target. " +
		"Supports comma-separated and range port lists (e.g. '22,80,443,8000-9000') or 'top1000'.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"target":{"type":"string",
				"description":"Hostname, IPv4, or IPv6 address to scan"},
			"ports":{"type":"string",
				"description":"Port spec: comma/range list '22,80,8000-9000' or 'top1000' (default 'top1000')"},
			"timeout_ms":{"type":"integer","minimum":100,
				"description":"Per-connection timeout in ms (default 1000)"},
			"concurrency":{"type":"integer","minimum":1,
				"description":"Parallel dial goroutines (default 64; max 256)"},
			"wall_timeout_ms":{"type":"integer","minimum":1000,
				"description":"Total scan wall-clock ceiling in ms (default 60000)"}
		},
		"required":["target"]
	}`),
	Required: []string{"target"},
	Risk:     risk.High,
	Group:    GroupSecurity,
	Handler:  portScanTCPHandler,
}

// portScanResult is the JSON output of port_scan_tcp.
type portScanResult struct {
	Target       string `json:"target"`
	Open         []int  `json:"open"`
	Closed       int    `json:"closed"`
	Filtered     int    `json:"filtered"`
	DurationMS   int64  `json:"duration_ms"`
	PortsScanned int    `json:"ports_scanned"`
}

// top1000Ports is a representative top-1000 TCP port list (port numbers only,
// no service labels — no nmap-copyright concern; values are public facts).
//
//nolint:gochecknoglobals
var top1000Ports = buildTop1000()

func buildTop1000() []int {
	// Frequently-encountered ports, covering the most common services.
	// This is a curated public-domain list of port numbers.
	raw := []int{
		1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37,
		42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106,
		109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199,
		211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389,
		406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500,
		512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593,
		616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705,
		711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873,
		880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995,
		999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024,
		1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036,
		1037, 1038, 1039, 1040, 1041, 1044, 1048, 1049, 1050, 1053, 1054, 1056,
		1058, 1059, 1064, 1065, 1066, 1069, 1071, 1074, 1080, 1110, 1234, 1433,
		1434, 1443, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1723, 1755, 1761,
		1801, 1900, 1935, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
		2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035,
		2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049, 2065, 2068,
		2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144,
		2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288,
		2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500,
		2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702,
		2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920,
		2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017,
		3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268,
		3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351, 3367,
		3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527, 3546,
		3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809,
		3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914,
		3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004,
		4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343,
		4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998,
		5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060,
		5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222,
		5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440, 5500,
		5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718,
		5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862,
		5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922,
		5925, 5950, 5952, 5959, 5960, 5961, 5962, 5987, 5988, 5989, 5998, 5999,
		6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100,
		6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547,
		6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699,
		6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004,
		7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443,
		7496, 7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921,
		7937, 7938, 7999, 8000, 8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021,
		8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087,
		8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200,
		8222, 8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500,
		8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873, 8888, 8899, 8994, 9000,
		9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090,
		9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290,
		9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618,
		9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998,
		9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025,
		10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628, 10629,
		10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782,
		13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742,
		16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988,
		18040, 18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000,
		20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800, 25734,
		25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715, 28201, 30000, 30718,
		30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775,
		32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354,
		33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176,
		44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157,
		49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999,
		50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103,
		51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600,
		56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331,
		64623, 64680, 65000, 65129, 65389,
	}
	return raw
}

func portScanTCPHandler(ctx context.Context, _ *Deps, p map[string]any) (string, error) {
	start := time.Now()

	target := strings.TrimSpace(str(p, "target"))
	if target == "" {
		return "", fmt.Errorf("port_scan_tcp: 'target' is required")
	}

	// Resolve hostname early to catch NXDOMAIN before dispatching goroutines.
	if _, err := net.LookupHost(target); err != nil {
		return "", fmt.Errorf("port_scan_tcp: DNS resolution failed for %q: %w", target, err)
	}

	portsSpec := str(p, "ports")
	if portsSpec == "" {
		portsSpec = "top1000"
	}
	timeoutMS := intOr(p, "timeout_ms", 1000)
	concurrency := intOr(p, "concurrency", 64)
	if concurrency > 256 {
		concurrency = 256
	}
	wallTimeoutMS := intOr(p, "wall_timeout_ms", 60000)

	ports, err := parsePorts(portsSpec)
	if err != nil {
		return "", fmt.Errorf("port_scan_tcp: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(wallTimeoutMS)*time.Millisecond)
	defer cancel()

	dialer := &net.Dialer{Timeout: time.Duration(timeoutMS) * time.Millisecond}

	portCh := make(chan int, concurrency)
	type dialResult struct {
		port     int
		open     bool
		filtered bool
	}
	resultCh := make(chan dialResult, len(ports))

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portCh {
				addr := net.JoinHostPort(target, strconv.Itoa(port))
				conn, dialErr := dialer.DialContext(ctx, "tcp", addr)
				if dialErr == nil {
					conn.Close()
					resultCh <- dialResult{port: port, open: true}
					continue
				}
				// Distinguish filtered (timeout) from closed (ECONNREFUSED).
				if netErr, ok := dialErr.(*net.OpError); ok && netErr.Timeout() {
					resultCh <- dialResult{port: port, filtered: true}
				} else {
					resultCh <- dialResult{port: port} // closed
				}
			}
		}()
	}

	go func() {
		for _, port := range ports {
			select {
			case <-ctx.Done():
				close(portCh)
				return
			case portCh <- port:
			}
		}
		close(portCh)
	}()

	wg.Wait()
	close(resultCh)

	var openPorts []int
	closed := 0
	filtered := 0
	for r := range resultCh {
		switch {
		case r.open:
			openPorts = append(openPorts, r.port)
		case r.filtered:
			filtered++
		default:
			closed++
		}
	}
	sort.Ints(openPorts)
	if openPorts == nil {
		openPorts = []int{}
	}

	res := portScanResult{
		Target:       target,
		Open:         openPorts,
		Closed:       closed,
		Filtered:     filtered,
		DurationMS:   time.Since(start).Milliseconds(),
		PortsScanned: len(ports),
	}
	b, err2 := json.Marshal(res)
	if err2 != nil {
		return "", err2
	}
	return string(b), nil
}

// parsePorts parses a port specification string into a sorted slice of ints.
// Accepted formats: "top1000", "80", "22,80,443", "8000-9000", or any combination.
func parsePorts(spec string) ([]int, error) {
	if strings.EqualFold(spec, "top1000") {
		return top1000Ports, nil
	}
	portSet := make(map[int]struct{})
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			for pp := lo; pp <= hi; pp++ {
				portSet[pp] = struct{}{}
			}
		} else {
			pp, err := strconv.Atoi(part)
			if err != nil || pp < 1 || pp > 65535 {
				return nil, fmt.Errorf("invalid port %q", part)
			}
			portSet[pp] = struct{}{}
		}
	}
	ports := make([]int, 0, len(portSet))
	for pp := range portSet {
		ports = append(ports, pp)
	}
	sort.Ints(ports)
	return ports, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// http_enum_common
// ─────────────────────────────────────────────────────────────────────────────

var httpEnumCommonSpec = Spec{
	Name: "http_enum_common",
	Description: "Wordlist-driven HTTP path enumeration. Pure-Go; ships with a built-in ~500-entry " +
		"common-paths wordlist (CC0-1.0, see promptzero://wordlists/common.txt). Performs soft-404 " +
		"canary detection to suppress false-positives. TLS certificate errors are ignored " +
		"(recon tool; targets often have invalid certs). Use before web exploitation to map " +
		"the attack surface.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"base_url":{"type":"string",
				"description":"Base URL, e.g. 'https://target/' or 'http://192.168.1.1'"},
			"wordlist":{"type":"string",
				"description":"Path to a wordlist file, 'builtin:common.txt', or 'promptzero://wordlists/common.txt' (default: builtin:common.txt)"},
			"extensions":{"type":"array","items":{"type":"string"},
				"description":"Extensions to append per path, e.g. ['php','html','bak']"},
			"match_codes":{"type":"array","items":{"type":"integer"},
				"description":"HTTP status codes to report as findings (default [200,204,301,302,307,401,403])"},
			"concurrency":{"type":"integer","minimum":1,
				"description":"Parallel HTTP goroutines (default 20; max 100)"},
			"timeout_ms":{"type":"integer","minimum":100,
				"description":"Per-request timeout in ms (default 5000)"},
			"wall_timeout_ms":{"type":"integer","minimum":1000,
				"description":"Total scan ceiling in ms (default 120000)"},
			"user_agent":{"type":"string",
				"description":"Override the User-Agent header. Default is a generic browser UA so the scan does not self-attribute the project — operators can pin a custom UA for engagements that require attribution or matching a specific tool."}
		},
		"required":["base_url"]
	}`),
	Required: []string{"base_url"},
	Risk:     risk.High,
	Group:    GroupSecurity,
	Handler:  httpEnumCommonHandler,
}

// httpFinding is one discovered path.
type httpFinding struct {
	Path   string `json:"path"`
	Status int    `json:"status"`
	Size   int64  `json:"size"`
}

// httpEnumResult is the JSON output of http_enum_common.
type httpEnumResult struct {
	BaseURL      string        `json:"base_url"`
	Found        []httpFinding `json:"found"`
	RequestsMade int           `json:"requests_made"`
	DurationMS   int64         `json:"duration_ms"`
	Wordlist     string        `json:"wordlist"`
	Extensions   []string      `json:"extensions"`
}

func httpEnumCommonHandler(ctx context.Context, _ *Deps, p map[string]any) (string, error) {
	start := time.Now()

	baseURL := strings.TrimSpace(str(p, "base_url"))
	if baseURL == "" {
		return "", fmt.Errorf("http_enum_common: 'base_url' is required")
	}
	// Normalise trailing slash.
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	// Validate URL.
	if _, err := url.ParseRequestURI(baseURL); err != nil {
		return "", fmt.Errorf("http_enum_common: invalid base_url: %w", err)
	}

	wordlistArg := strings.TrimSpace(str(p, "wordlist"))
	if wordlistArg == "" {
		wordlistArg = "builtin:common.txt"
	}

	// Load wordlist entries.
	var wordlistLines []string
	var wordlistLabel string

	switch {
	case strings.HasPrefix(wordlistArg, "builtin:"):
		name := strings.TrimPrefix(wordlistArg, "builtin:")
		raw, err := builtinWordlist(name)
		if err != nil {
			return "", fmt.Errorf("http_enum_common: %w", err)
		}
		wordlistLines = parseWordlistLines(raw)
		wordlistLabel = "builtin:" + name

	case strings.HasPrefix(wordlistArg, "promptzero://wordlists/"):
		name := strings.TrimPrefix(wordlistArg, "promptzero://wordlists/")
		raw, err := builtinWordlist(name)
		if err != nil {
			return "", fmt.Errorf("http_enum_common: %w", err)
		}
		wordlistLines = parseWordlistLines(raw)
		wordlistLabel = "promptzero://wordlists/" + name

	default:
		f, err := os.Open(wordlistArg) //nolint:gosec // operator-controlled path
		if err != nil {
			return "", fmt.Errorf("http_enum_common: open wordlist: %w", err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				wordlistLines = append(wordlistLines, line)
			}
		}
		wordlistLabel = wordlistArg
	}

	// Parse extensions.
	var extensions []string
	if extsRaw, ok := p["extensions"].([]any); ok {
		for _, v := range extsRaw {
			if s, ok := v.(string); ok && s != "" {
				extensions = append(extensions, strings.TrimPrefix(s, "."))
			}
		}
	}

	// Parse match_codes.
	matchCodes := map[int]bool{200: true, 204: true, 301: true, 302: true, 307: true, 401: true, 403: true}
	if codesRaw, ok := p["match_codes"].([]any); ok && len(codesRaw) > 0 {
		matchCodes = make(map[int]bool, len(codesRaw))
		for _, v := range codesRaw {
			if f, ok := v.(float64); ok {
				matchCodes[int(f)] = true
			}
		}
	}

	concurrency := intOr(p, "concurrency", 20)
	if concurrency > 100 {
		concurrency = 100
	}
	timeoutMS := intOr(p, "timeout_ms", 5000)
	wallTimeoutMS := intOr(p, "wall_timeout_ms", 120000)
	userAgent := str(p, "user_agent")
	if userAgent == "" {
		// Default to a generic Chrome UA rather than the project name.
		// Self-attributing in `User-Agent` (the pre-v0.20.0 default,
		// "PromptZero/0.5") gave DFIR a free indicator-of-tooling marker
		// every time a recon scan landed in a target's web logs. Operators
		// who *want* attribution still get it via the user_agent argument.
		userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
			"(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(wallTimeoutMS)*time.Millisecond)
	defer cancel()

	// Build HTTP client — disable redirect following; ignore TLS errors.
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // recon tool; pentest targets often have invalid certs
		MaxIdleConnsPerHost: concurrency,
		DisableCompression:  true,
	}
	client := &http.Client{
		Timeout:   time.Duration(timeoutMS) * time.Millisecond,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // report redirect as a finding, not destination
		},
	}

	// Soft-404 canary: probe a random path to detect servers that return 200
	// for all requests.  We filter findings whose size matches the canary ±5%.
	canaryPath := fmt.Sprintf("promptzero-canary-%d", rand.Int63()) //nolint:gosec // rand for canary path, not security
	var canarySize int64 = -1
	if canaryReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+canaryPath, nil); err == nil {
		canaryReq.Header.Set("User-Agent", userAgent)
		if resp, err := client.Do(canaryReq); err == nil {
			canarySize = resp.ContentLength
			resp.Body.Close()
		}
	}

	// Expand wordlist with extensions.
	var paths []string
	for _, line := range wordlistLines {
		line = strings.TrimPrefix(line, "/")
		paths = append(paths, line)
		for _, ext := range extensions {
			paths = append(paths, line+"."+ext)
		}
	}

	pathCh := make(chan string, concurrency)
	type scanResult struct {
		path   string
		status int
		size   int64
	}
	resultCh := make(chan scanResult, 256)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range pathCh {
				fullURL := baseURL + path
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
				if err != nil {
					continue
				}
				req.Header.Set("User-Agent", userAgent)
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				size := resp.ContentLength
				status := resp.StatusCode
				resp.Body.Close()
				if matchCodes[status] {
					resultCh <- scanResult{path: "/" + path, status: status, size: size}
				}
			}
		}()
	}

	var requestsMade int
	go func() {
		for _, path := range paths {
			select {
			case <-ctx.Done():
				close(pathCh)
				return
			case pathCh <- path:
				requestsMade++
			}
		}
		close(pathCh)
	}()

	wg.Wait()
	close(resultCh)

	var findings []httpFinding
	for r := range resultCh {
		// Soft-404 filter: skip if body size matches canary within ±5%.
		if canarySize > 0 && r.size > 0 {
			diff := r.size - canarySize
			if diff < 0 {
				diff = -diff
			}
			if float64(diff)/float64(canarySize) <= 0.05 {
				continue
			}
		}
		findings = append(findings, httpFinding{Path: r.path, Status: r.status, Size: r.size})
	}
	if findings == nil {
		findings = []httpFinding{}
	}

	exts := extensions
	if exts == nil {
		exts = []string{}
	}

	res := httpEnumResult{
		BaseURL:      baseURL,
		Found:        findings,
		RequestsMade: requestsMade,
		DurationMS:   time.Since(start).Milliseconds(),
		Wordlist:     wordlistLabel,
		Extensions:   exts,
	}
	b, err := json.Marshal(res)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// parseWordlistLines strips comment and blank lines from a raw wordlist string.
func parseWordlistLines(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}
