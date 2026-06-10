package macaroon

import (
	"encoding/base64"
	"errors"
	"strings"
)

// DecodeBase64 decodes the base64-wrapped form a macaroon ships in (e.g. the
// part of a PyPI token after the "pypi-" prefix) and parses it. pymacaroons
// emits URL-safe, unpadded base64; cross-implementation tooling may emit
// standard base64; so DecodeBase64 trims surrounding whitespace and padding and
// tries the URL-safe and standard alphabets in turn, returning the first that
// both decodes and yields a valid macaroon.
func DecodeBase64(s string) (*Macaroon, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "=")
	if s == "" {
		return nil, errors.New("empty macaroon")
	}
	var firstErr error
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding} {
		raw, err := enc.DecodeString(s)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		m, err := Decode(raw)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return m, nil
	}
	return nil, firstErr
}
