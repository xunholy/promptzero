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

// NewClassifier returns a Classifier pre-loaded with all 26 protocol decoders.
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
		},
	}
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

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Confidence > matches[j].Confidence
	})

	if n > 0 && len(matches) > n {
		matches = matches[:n]
	}
	return matches
}
