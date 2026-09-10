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

func rankScoped(id string, sev finding.Severity, scope finding.Scope, e finding.Exploit) finding.Finding {
	e.Scope = scope
	return finding.Finding{ID: id, Package: "p", Severity: sev, Exploit: e}
}

func TestScopeDemotesDevAfterProdAtEqualSeverity(t *testing.T) {
	e := finding.Exploit{EPSS: 0.5, EPSSKnown: true}
	dev := rankScoped("CVE-D", finding.SevHigh, finding.ScopeDev, e)
	for _, above := range []finding.Scope{finding.ScopeProd, finding.ScopeUnknown} {
		prod := rankScoped("CVE-P", finding.SevHigh, above, e)
		if !finding.Less(prod, dev) || finding.Less(dev, prod) {
			t.Fatalf("scope %q must rank strictly before dev at equal severity", above)
		}
		fs := []finding.Finding{dev, prod}
		finding.Rank(fs)
		if fs[0].ID != "CVE-P" {
			t.Fatalf("ranked %s first: prod and unknown must sort before dev", fs[0].ID)
		}
	}
}

func TestRawEPSSStillBindsWithinEachScopeClass(t *testing.T) {
	for _, scope := range []finding.Scope{finding.ScopeDev, finding.ScopeProd} {
		lower := rankScoped("CVE-1", finding.SevHigh, scope, finding.Exploit{EPSS: 0.04, EPSSKnown: true})
		upper := rankScoped("CVE-2", finding.SevHigh, scope, finding.Exploit{EPSS: 0.5, EPSSKnown: true})
		if !finding.Less(upper, lower) || finding.Less(lower, upper) {
			t.Fatalf("scope %q: equal scope must still order by raw EPSS", scope)
		}
	}
}

func TestSeverityOutranksScopeDemotion(t *testing.T) {
	e := finding.Exploit{EPSS: 0.5, EPSSKnown: true}
	prodLow := rankScoped("CVE-L", finding.SevLow, finding.ScopeProd, e)
	devCritical := rankScoped("CVE-C", finding.SevCritical, finding.ScopeDev, e)

	fs := []finding.Finding{prodLow, devCritical}
	finding.Rank(fs)
	if fs[0].ID != "CVE-C" {
		t.Fatalf("ranked %s first: severity must dominate scope, dev stays above a lower severity", fs[0].ID)
	}
}
