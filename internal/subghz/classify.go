// SPDX-License-Identifier: AGPL-3.0-or-later

package subghz

import (
	"sort"

	"github.com/xunholy/promptzero/internal/subghz/protocols"
)

// Protocol is the interface every protocol decoder must implement.
// It wraps the protocols.Protocol interface so callers can also register
// custom decoders that satisfy the same contract.
type Protocol interface {
	// Name returns the human-readable protocol name.
	Name() string

	// BitRate returns the nominal bit rate in baud.
	BitRate() float64

	// Decode attempts to decode the pulse sequence. Returns a protocols.Result
	// and nil on success, or a non-nil error when the pulses do not match the
	// expected sync/timing pattern.
	Decode(pulses []int) (protocols.Result, error)
}

// Result is the output of a successful protocol decode, visible to callers
// of the subghz package.
type Result = protocols.Result

// Match pairs a decode result with any extra classifier metadata.
type Match struct {
	Result
}

// Classifier tries every registered protocol against a pulse sequence and
// returns the top matches by confidence.
type Classifier struct {
	protos []Protocol
}

// NewClassifier returns a Classifier pre-loaded with every built-in protocol
// decoder.
func NewClassifier() *Classifier {
	return &Classifier{
		protos: []Protocol{
			protocols.PrincetonPT2262{},
			protocols.CAME{},
			protocols.HoltekHT12E{},
			protocols.Linear{},
			protocols.NICEFlorS{},
			protocols.KeeLoqHCS{},
			protocols.FaacSLH{},
			protocols.Beninca{},
			protocols.Prastel{},
			protocols.Ansonic{},
			protocols.Smartgate{},
			protocols.Aerolite{},
			protocols.Doitrand{},
			// Hormann's strict fixed-pattern gate (0xFF000000003) makes it the
			// most specific 44-bit PWM match; ordered before SecplusV1, whose
			// gate-less 40-bit rolling-code reader also accepts a Hormann
			// frame's prefix, so the more-specific protocol wins the tie.
			protocols.Hormann{},
			protocols.SecplusV1{},
			protocols.Magicode{},
			protocols.HoneywellWS{},
			protocols.PrincetonHoltek{},
			protocols.CAMETwin{},
			protocols.Aprimatic{},
			protocols.PhoenixV2{},
			protocols.NiceFLO{},
			protocols.BFTMitto{},
			protocols.SomfyRTS{},
			protocols.Marantec{},
			protocols.BETT{},
			protocols.SecplusV2{},
			protocols.GateTX{},
			protocols.SMC5326{},
			protocols.Megacode{},
			protocols.Magellan{},
			protocols.Mastercode{},
			protocols.GangQi{},
			protocols.Dooya{},
			protocols.Marantec24{},
			protocols.IntertechnoV3{},
		},
	}
}

// ProtocolNames returns the Name() of every registered decoder, in classifier
// (priority) order. It is the single source of truth for tool descriptions and
// docs that enumerate the supported protocols, so those can be generated rather
// than hand-maintained (which historically drifted out of sync as protocols
// were added).
func (c *Classifier) ProtocolNames() []string {
	names := make([]string, len(c.protos))
	for i, p := range c.protos {
		names[i] = p.Name()
	}
	return names
}

// Classify attempts every registered protocol decoder against pulses and
// returns the top-n matches ordered by descending confidence. When n <= 0
// all matches with confidence > 0 are returned.
func (c *Classifier) Classify(pulses []int, n int) []Match {
	if len(pulses) == 0 {
		return nil
	}

	var matches []Match
	for _, p := range c.protos {
		res, err := p.Decode(pulses)
		if err != nil || res.Confidence <= 0 {
			continue
		}
		matches = append(matches, Match{Result: res})
	}

	// Order by descending confidence, with a deterministic tiebreak on
	// protocol name. sort.Slice is NOT stable, so equal-confidence matches
	// previously surfaced in arbitrary order — a real frame that legitimately
	// ties (e.g. a 40-bit PWM code accepted by both a gated protocol and a
	// gate-less reader at full confidence) produced a non-deterministic top
	// match, flaking CI run-to-run. The name tiebreak makes Classify a total,
	// reproducible order; see TestClassifyDeterministicOrder.
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Confidence != matches[j].Confidence {
			return matches[i].Confidence > matches[j].Confidence
		}
		return matches[i].Protocol < matches[j].Protocol
	})

	if n > 0 && len(matches) > n {
		matches = matches[:n]
	}
	return matches
}
