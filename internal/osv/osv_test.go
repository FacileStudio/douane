package osv

import (
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
)

func TestFixedInPicksTheInstalledBranch(t *testing.T) {
	a := osvAffected("form-data", "npm", "SEMVER", Event{Fixed: "2.5.6"}, Event{Fixed: "4.0.6"})
	v := Vuln{Affected: []Affected{a}}
	pkg := finding.Package{Name: "form-data", Ecosystem: "npm", Version: "4.0.5"}
	if got := FixedIn(v, pkg); got != "4.0.6" {
		t.Fatalf("FixedIn = %q, want 4.0.6 (2.5.6 is a lower branch, not a fix)", got)
	}
	pkg.Version = "9.0.0"
	if got := FixedIn(v, pkg); got != "" {
		t.Fatalf("FixedIn = %q, want empty when no fix exists above the installed version", got)
	}
}

func TestFixedInMatchesTheEcosystem(t *testing.T) {
	a := osvAffected("log4j", "Maven", "ECOSYSTEM", Event{Fixed: "2.17.0"})
	v := Vuln{Affected: []Affected{a}}
	if got := FixedIn(v, finding.Package{Name: "log4j", Ecosystem: "npm", Version: "1.0.0"}); got != "" {
		t.Fatalf("FixedIn = %q, want empty — same name, different ecosystem, different package", got)
	}
	if got := FixedIn(v, finding.Package{Name: "log4j", Ecosystem: "Maven", Version: "2.0.0"}); got != "2.17.0" {
		t.Fatalf("FixedIn = %q, want 2.17.0", got)
	}
}

// A Go module path carries its major suffix, so /v5 and the unsuffixed path are
// two packages with two fixes and an exact match is the only correct one.
func TestFixedInKeepsTheGoMajorSuffix(t *testing.T) {
	v := Vuln{Affected: []Affected{
		osvAffected("github.com/go-chi/chi", "Go", "SEMVER", Event{Fixed: "1.5.5"}),
		osvAffected("github.com/go-chi/chi/v5", "Go", "SEMVER", Event{Fixed: "5.2.4"}),
	}}
	pkg := finding.Package{Name: "github.com/go-chi/chi/v5", Ecosystem: "Go", Version: "5.2.3"}
	if got := FixedIn(v, pkg); got != "5.2.4" {
		t.Fatalf("FixedIn = %q, want 5.2.4", got)
	}
}

func TestFixedInWalksGoMajorBranches(t *testing.T) {
	branches := []Event{
		{Introduced: "0"}, {Fixed: "1.23.7"},
		{Introduced: "1.24.0-0"}, {Fixed: "1.24.1"},
	}
	v := Vuln{Affected: []Affected{osvAffected("stdlib", "Go", "SEMVER", branches...)}}
	pkg := finding.Package{Name: "stdlib", Ecosystem: "Go", Version: "1.24.0"}
	if got := FixedIn(v, pkg); got != "1.24.1" {
		t.Fatalf("FixedIn = %q, want 1.24.1 for a 1.24 toolchain", got)
	}
	pkg.Version = "1.22.0"
	if got := FixedIn(v, pkg); got != "1.23.7" {
		t.Fatalf("FixedIn = %q, want 1.23.7 for a 1.22 toolchain", got)
	}
}

func TestFixedInIgnoresLastAffectedAndLimit(t *testing.T) {
	events := []Event{{Introduced: "1.0.0"}, {LastAffected: "1.5.0"}, {Limit: "2.0.0"}}
	v := Vuln{Affected: []Affected{osvAffected("serde", "crates.io", "SEMVER", events...)}}
	pkg := finding.Package{Name: "serde", Ecosystem: "crates.io", Version: "1.2.0"}
	if got := FixedIn(v, pkg); got != "" {
		t.Fatalf("FixedIn = %q, want empty — last_affected and limit name affected versions, not fixes", got)
	}
}

func TestFixedInSkipsGitRangesAndSaysSo(t *testing.T) {
	commits := []Event{
		{Introduced: "0000000000000000000000000000000000000000"},
		{Fixed: "9f1b4d2e7a3c5b8d0e1f2a3b4c5d6e7f80912345"},
	}
	a := osvAffected("github.com/go-chi/chi/v5", "Go", "GIT", commits...)
	v := Vuln{ID: "CVE-2026-72816", Affected: []Affected{a}}
	pkg := finding.Package{Name: "github.com/go-chi/chi/v5", Ecosystem: "Go", Version: "5.2.3"}
	if got := FixedIn(v, pkg); got != "" {
		t.Fatalf("FixedIn = %q, want empty — a commit hash is not a version", got)
	}
	gaps := RangeGaps(v, pkg)
	if len(gaps) != 1 || gaps[0].Kind != finding.GapRange {
		t.Fatalf("RangeGaps = %v, want one range gap — a skipped GIT range must not be silent", gaps)
	}
}

func TestRangeGapsStaysQuietWhenAVersionRangeExists(t *testing.T) {
	a := osvAffected("tokio", "crates.io", "GIT", Event{Introduced: "0"})
	a.Ranges = append(a.Ranges, Range{Type: "SEMVER", Events: []Event{{Fixed: "1.20.1"}}})
	v := Vuln{ID: "GHSA-test", Affected: []Affected{a}}
	pkg := finding.Package{Name: "tokio", Ecosystem: "crates.io", Version: "1.20.0"}
	if got := FixedIn(v, pkg); got != "1.20.1" {
		t.Fatalf("FixedIn = %q, want 1.20.1", got)
	}
	if gaps := RangeGaps(v, pkg); len(gaps) != 0 {
		t.Fatalf("RangeGaps = %v, want none — the version range answered the question", gaps)
	}
}
