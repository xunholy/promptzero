// SPDX-License-Identifier: AGPL-3.0-or-later

// Package snowflake decodes a Snowflake ID — the 64-bit identifier used by
// Discord, Twitter/X, Instagram and others — into its embedded creation
// timestamp. A Snowflake packs a 41-bit millisecond timestamp (counted from a
// platform-specific epoch) in its high bits, then machine/worker and sequence
// bits. Decoding a Snowflake is a standard OSINT technique: a Discord user,
// message, channel or guild ID, or a tweet/X-post ID, reveals exactly **when
// the object was created** (account age, message timing, enumeration). This is
// the integer/social-media counterpart to the string identifier decoders
// (internal/uuidinfo, internal/objectid, internal/ulid). Pure offline transform;
// no network or device.
//
// # Wrap-vs-native judgement
//
// Native. A Snowflake is `timestamp_ms = (id >> 22) + epoch`, then a handful of
// low-bit fields — a shift, an add, and some masks. There is nothing to wrap.
// Consistent with the other in-tree identifier decoders.
//
// # Verifiable / no confidently-wrong output
//
// A bare Snowflake does NOT identify its platform, and the same integer yields a
// different timestamp under each platform's epoch. To avoid a confidently-wrong
// single answer, the decoder reports a labelled candidate per known platform
// (Discord and Twitter/X — which share the 41-bit-timestamp / 22-bit-tail
// layout, differing only in epoch and the machine-bit split) and asserts none;
// the operator selects by where the ID was found. Anchored to Discord's own
// documented example: 175928847299117063 → 2016-04-30T11:18:25.796Z (worker 1,
// process 0, increment 7). Instagram and other variants use a different bit
// layout and are deliberately not decoded (a wrong field split would be
// confidently-wrong). A non-numeric / out-of-range-uint64 input is rejected.
package snowflake

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Epochs (milliseconds since the Unix epoch).
const (
	discordEpoch = 1420070400000 // 2015-01-01T00:00:00Z
	twitterEpoch = 1288834974657 // 2010-11-04T01:42:54.657Z
)

// Candidate is the decoding of a Snowflake under one platform's epoch + layout.
type Candidate struct {
	Platform     string `json:"platform"`
	EpochMs      int64  `json:"epoch_ms"`
	TimestampUTC string `json:"timestamp_utc"`
	UnixMillis   int64  `json:"unix_millis"`
	// Discord splits the 10 middle bits into worker (5) + process (5); Twitter/X
	// uses all 10 as a single machine id. Only the relevant fields are set.
	WorkerID  *int `json:"worker_id,omitempty"`
	ProcessID *int `json:"process_id,omitempty"`
	MachineID *int `json:"machine_id,omitempty"`
	Sequence  int  `json:"sequence"`
}

// Result is the decoded view of a Snowflake ID.
type Result struct {
	Snowflake     string      `json:"snowflake"`
	TimestampBits uint64      `json:"timestamp_bits"` // id >> 22, before adding any epoch
	Candidates    []Candidate `json:"candidates"`
	Note          string      `json:"note,omitempty"`
}

// Decode parses a decimal Snowflake ID. If platform is "" it returns candidates
// for all known platforms; a specific platform ("discord" / "twitter" / "x")
// returns just that one.
func Decode(id, platform string) (*Result, error) {
	s := strings.TrimSpace(id)
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("snowflake: %q is not a valid 64-bit unsigned integer", id)
	}
	r := &Result{Snowflake: s, TimestampBits: v >> 22}

	seq := int(v & 0xfff)
	worker := int((v >> 17) & 0x1f)
	process := int((v >> 12) & 0x1f)
	machine := int((v >> 12) & 0x3ff)

	discord := Candidate{
		Platform: "Discord", EpochMs: discordEpoch,
		WorkerID: &worker, ProcessID: &process, Sequence: seq,
	}
	setTime(&discord, r.TimestampBits, discordEpoch)

	twitter := Candidate{
		Platform: "Twitter/X", EpochMs: twitterEpoch,
		MachineID: &machine, Sequence: seq,
	}
	setTime(&twitter, r.TimestampBits, twitterEpoch)

	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "discord":
		r.Candidates = []Candidate{discord}
	case "twitter", "x", "twitter/x":
		r.Candidates = []Candidate{twitter}
	case "":
		r.Candidates = []Candidate{discord, twitter}
		r.Note = "a bare Snowflake does not identify its platform; the timestamp depends on the platform epoch. " +
			"Pick the candidate matching where you found the ID. Discord and Twitter/X share the " +
			"41-bit-timestamp + 22-bit-tail layout (differing only in epoch and the machine-bit split); " +
			"Instagram and other Snowflake variants use a different layout and are not decoded here."
	default:
		return nil, fmt.Errorf("snowflake: unknown platform %q (use discord, twitter, or omit for all)", platform)
	}
	return r, nil
}

func setTime(c *Candidate, tsBits uint64, epoch int64) {
	ms := int64(tsBits) + epoch
	c.UnixMillis = ms
	c.TimestampUTC = time.UnixMilli(ms).UTC().Format(time.RFC3339Nano)
}
