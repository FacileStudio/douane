package osv

import (
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

// gitRange is the range type whose events are commit hashes rather than
// versions. Handing a 40-character hash to a version comparator does not fail
// loudly: the range simply never matches, and the finding quietly loses its
// fix. So it is skipped here and reported by RangeGaps.
const gitRange = "GIT"

// FixedIn returns the version that fixes this advisory on the branch the
// installed version sits on. Advisories carry one range per major branch, so
// the lowest fix strictly above the installed version is the relevant one.
// An empty result means no fix exists for that branch.
func FixedIn(v Vuln, pkg finding.Package) string {
	best := ""
	for _, a := range v.Affected {
		if !affects(a, pkg) {
			continue
		}
		for _, r := range a.Ranges {
			if !evaluable(r) {
				continue
			}
			best = lowestFixAbove(r, pkg.Version, best)
		}
	}
	return best
}

// RangeGaps reports what FixedIn could not evaluate for pkg. FixedIn answers
// with a version and has nowhere to say "I could not tell", so a caller
// building a finding has to ask here as well; a skipped GIT range is otherwise
// indistinguishable from an advisory with no fix.
func RangeGaps(v Vuln, pkg finding.Package) []finding.Gap {
	skipped, usable := 0, 0
	for _, a := range v.Affected {
		if !affects(a, pkg) {
			continue
		}
		for _, r := range a.Ranges {
			if evaluable(r) {
				usable++
				continue
			}
			skipped++
		}
	}
	if skipped == 0 || usable > 0 {
		return nil
	}
	return []finding.Gap{{
		Kind:    finding.GapRange,
		Subject: pkg.Name,
		Detail:  v.ID + ": commit ranges only, which a lockfile version cannot be compared against",
	}}
}

// lowestFixAbove reads only fixed events. An advisory's other terminators,
// last_affected and limit, name a version that is still affected, so treating
// either as a fix would advertise an upgrade that does not exist.
func lowestFixAbove(r Range, installed, best string) string {
	for _, e := range r.Events {
		best = preferFix(e.Fixed, installed, best)
	}
	return best
}

func preferFix(candidate, installed, best string) string {
	if candidate == "" || compareVersions(candidate, installed) <= 0 {
		return best
	}
	if best == "" || compareVersions(candidate, best) < 0 {
		return candidate
	}
	return best
}

// affects reports whether an affected entry is about this package. The
// ecosystem is part of the match because names collide across them, and in Go
// the "/vN" major suffix is part of the module path: an advisory lists /v5, /v4
// and the unsuffixed path as three separate entries with three separate fixes.
func affects(a Affected, pkg finding.Package) bool {
	return a.Package.Name == pkg.Name && sameEcosystem(a.Package.Ecosystem, pkg.Ecosystem)
}

// sameEcosystem compares OSV ecosystem names ignoring the ":release" suffix a
// distribution appends, since douane names the base ecosystem.
func sameEcosystem(a, b string) bool {
	a, _, _ = strings.Cut(a, ":")
	b, _, _ = strings.Cut(b, ":")
	return strings.EqualFold(a, b)
}

func evaluable(r Range) bool { return !strings.EqualFold(r.Type, gitRange) }
