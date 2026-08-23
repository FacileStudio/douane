package finding_test

import (
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
)

func rankOne(id, pkg string, sev finding.Severity, e finding.Exploit) finding.Finding {
	return finding.Finding{ID: id, Package: pkg, Severity: sev, Exploit: e}
}

func TestUnscoredCriticalOutranksNoiseFloorLow(t *testing.T) {
	critical := rankOne("CVE-A", "a", finding.SevCritical, finding.Exploit{})
	low := rankOne("CVE-B", "b", finding.SevLow, finding.Exploit{EPSS: 0.0004, EPSSKnown: true})

	fs := []finding.Finding{low, critical}
	finding.Rank(fs)
	if fs[0].ID != "CVE-A" {
		t.Fatalf("ranked %s first: an unscored CRITICAL must not sink below a LOW scored 0.04%%", fs[0].ID)
	}
}

func TestRealLikelihoodStillOutranksSeverity(t *testing.T) {
	low := rankOne("CVE-B", "b", finding.SevLow, finding.Exploit{EPSS: 0.5, EPSSKnown: true})
	critical := rankOne("CVE-A", "a", finding.SevCritical, finding.Exploit{})

	fs := []finding.Finding{critical, low}
	finding.Rank(fs)
	if fs[0].ID != "CVE-B" {
		t.Fatalf("ranked %s first: a LOW at 50%% likelihood is the one to open first", fs[0].ID)
	}
}

func TestKnownExploitedOutranksEverything(t *testing.T) {
	kev := rankOne("CVE-K", "k", finding.SevLow, finding.Exploit{KEV: true})
	worst := rankOne("CVE-W", "w", finding.SevCritical, finding.Exploit{EPSS: 0.99, EPSSKnown: true})

	fs := []finding.Finding{worst, kev}
	finding.Rank(fs)
	if fs[0].ID != "CVE-K" {
		t.Fatalf("ranked %s first: KEV is precedence, not a term in a sum", fs[0].ID)
	}
}
