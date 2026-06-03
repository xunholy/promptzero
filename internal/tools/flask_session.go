// flask_session.go — host-side Flask (itsdangerous) session-cookie
// decode / verify / forge Spec, delegating to internal/flasksession.
//
// Wrap-vs-native: native — Flask signs sessions with HMAC-SHA1 under a key
// derived as HMAC-SHA1(SECRET_KEY, "cookie-session"); base64url segments,
// optional zlib. It is the web-pentest analogue of the JWT trio: a Flask
// session is signed-not-encrypted (decode reads it without the key), and a weak
// or leaked SECRET_KEY lets an attacker forge an arbitrary session (the
// flask-unsign attack). Offline compute over operator-supplied strings; no
// network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/flasksession"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(flaskSessionSpec)
}

var flaskSessionSpec = Spec{
	Name: "flask_session",
	Description: "Decode, verify or forge a Flask (itsdangerous) session cookie — the web-pentest analogue " +
		"of the JWT trio. A Flask session is signed, not encrypted, so its payload is readable by anyone; an " +
		"app with a weak or leaked SECRET_KEY can be impersonated by forging an arbitrary session (the " +
		"flask-unsign attack).\n\n" +
		"Modes (inferred): **decode** — pass **cookie** only, returns the JSON payload (transparently " +
		"zlib-inflated) + timestamp, no key needed. **verify** — pass **cookie** + **secret** (one " +
		"candidate) or **secrets** (a list — the weak-SECRET_KEY test, reporting which validates). " +
		"**forge** — pass **payload** (JSON) + **secret** to mint a validly-signed cookie for an authorized " +
		"test (e.g. {\"admin\":true}); optional **timestamp** (unix, default now). Optional **salt** " +
		"(default Flask's \"cookie-session\").\n\n" +
		"Offline compute over operator-supplied strings — no network, no device, transmits nothing, so it " +
		"is Low risk. Verified in-tree byte-for-byte against the reference itsdangerous library. " +
		"Wrap-vs-native: native — HMAC-SHA1 + base64url + zlib, standard-library only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"cookie":{"type":"string","description":"The Flask session cookie (decode / verify)."},
			"secret":{"type":"string","description":"A candidate SECRET_KEY (verify), or the key to sign with (forge)."},
			"secrets":{"type":"array","items":{"type":"string"},"description":"Candidate SECRET_KEYs to test (verify) — reports which, if any, validates."},
			"payload":{"type":"string","description":"JSON payload to sign (forge mode)."},
			"salt":{"type":"string","description":"itsdangerous salt (default \"cookie-session\")."},
			"timestamp":{"type":"integer","description":"Forge-mode unix timestamp (default: now)."}
		}
	}`),
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   flaskSessionHandler,
}

func flaskSessionHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	salt := str(p, "salt")

	// Forge mode: a payload to sign.
	if payload := strings.TrimSpace(str(p, "payload")); payload != "" {
		secret := str(p, "secret")
		if secret == "" {
			return "", fmt.Errorf("flask_session: forge needs 'secret' (the SECRET_KEY to sign with)")
		}
		ts := int64(intOr(p, "timestamp", int(time.Now().Unix())))
		cookie, err := flasksession.Sign(payload, secret, salt, ts)
		if err != nil {
			return "", fmt.Errorf("flask_session: %w", err)
		}
		out, _ := json.MarshalIndent(map[string]any{"mode": "forge", "cookie": cookie}, "", "  ")
		return string(out), nil
	}

	cookie := strings.TrimSpace(str(p, "cookie"))
	if cookie == "" {
		return "", fmt.Errorf("flask_session: 'cookie' is required (or 'payload' to forge)")
	}
	sess, derr := flasksession.Decode(cookie)
	if derr != nil {
		return "", fmt.Errorf("flask_session: %w", derr)
	}

	// Collect candidate secrets.
	var secrets []string
	if s := str(p, "secret"); s != "" {
		secrets = append(secrets, s)
	}
	if raw, ok := p["secrets"].([]any); ok {
		for _, v := range raw {
			if s, ok := v.(string); ok && s != "" {
				secrets = append(secrets, s)
			}
		}
	}

	if len(secrets) == 0 {
		out, _ := json.MarshalIndent(map[string]any{"mode": "decode", "session": sess}, "", "  ")
		return string(out), nil
	}

	for _, s := range secrets {
		ok, _ := flasksession.Verify(cookie, s, salt)
		if ok {
			out, _ := json.MarshalIndent(map[string]any{
				"mode": "verify", "valid": true, "matched_secret": s,
				"candidates_tried": len(secrets), "session": sess,
			}, "", "  ")
			return string(out), nil
		}
	}
	out, _ := json.MarshalIndent(map[string]any{
		"mode": "verify", "valid": false, "candidates_tried": len(secrets),
		"note": "no supplied SECRET_KEY validates the signature", "session": sess,
	}, "", "  ")
	return string(out), nil
}
