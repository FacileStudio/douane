package finding_test

import (
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
)

func rankExploits() []finding.Exploit {
	var out []finding.Exploit
	for _, kev := range []bool{false, true} {
		for _, known := range []bool{false, true} {
			for _, epss := range []float64{0, 0.0004, 0.008, 0.04, 0.5} {
				out = append(out, finding.Exploit{EPSS: epss, EPSSKnown: known, KEV: kev})
			}
		}
	}
	return out
}

func rankCorpus() []finding.Finding {
	severities := []finding.Severity{
		finding.SevUnknown, finding.SevLow, finding.SevMedium,
		finding.SevHigh, finding.SevCritical,
	}
	var out []finding.Finding
	for _, e := range rankExploits() {
		for _, sev := range severities {
			out = append(out, rankOne("CVE-1", "p", sev, e))
		}
	}
	return out
}

func rankBreaksTransitivity(a, b, c finding.Finding) bool {
	return finding.Less(a, b) && finding.Less(b, c) && !finding.Less(a, c)
}

func rankIntransitiveWith(a, b finding.Finding, corpus []finding.Finding) (finding.Finding, bool) {
	for _, c := range corpus {
		if rankBreaksTransitivity(a, b, c) {
			return c, true
		}
	}
	return finding.Finding{}, false
}

func TestLessIsIrreflexive(t *testing.T) {
	for _, a := range rankCorpus() {
		if finding.Less(a, a) {
			t.Fatalf("Less is not irreflexive at %+v", a)
		}
	}
}

// The ordering must be a strict weak ordering or sort.SliceStable may return
// any permutation at all, which is how a ranking stops being reproducible
// between runs on identical input.
func TestLessIsAsymmetricAndTransitive(t *testing.T) {
	corpus := rankCorpus()
	for i, a := range corpus {
		for _, b := range corpus[i:] {
			if finding.Less(a, b) && finding.Less(b, a) {
				t.Fatalf("Less is not asymmetric for %+v vs %+v", a, b)
			}
			if c, bad := rankIntransitiveWith(a, b, corpus); bad {
				t.Fatalf("not transitive: %+v < %+v < %+v but not a < c", a, b, c)
			}
		}
	}
}
