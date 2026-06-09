// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/subghz"
)

// TestSubghzClassifyDescription guards against the protocol list in the tool
// description drifting out of sync with the classifier's registered decoders —
// a recurring failure mode before the description was generated from the
// roster. It asserts the rendered description names every registered protocol
// and reports the correct count.
func TestSubghzClassifyDescription(t *testing.T) {
	names := subghz.NewClassifier().ProtocolNames()
	desc := subghzClassifySpec.Description

	if desc == "" {
		t.Fatal("subghz_classify Description is empty")
	}

	wantCount := fmt.Sprintf("%d most common Sub-GHz protocols", len(names))
	if !strings.Contains(desc, wantCount) {
		t.Errorf("description missing protocol count %q\n  description: %s", wantCount, desc)
	}

	for _, n := range names {
		if !strings.Contains(desc, n) {
			t.Errorf("description omits registered protocol %q", n)
		}
	}
}
