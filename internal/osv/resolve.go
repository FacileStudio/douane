package osv

import (
	"sort"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

// Canonical picks the identifier a vulnerability should be reported under,
// preferring a CVE so the same flaw carries one name across ecosystems, and
// returns the remaining identifiers as aliases.
func Canonical(v Vuln) (string, []string) {
	all := append([]string{v.ID}, v.Aliases...)
	sort.Strings(all)

	best, rank := v.ID, idRank(v.ID)
	for _, id := range all {
		if r := idRank(id); r > rank {
			best, rank = id, r
		}
	}
	aliases := make([]string, 0, len(all))
	for _, id := range all {
		if id != best {
			aliases = append(aliases, id)
		}
	}
	return best, aliases
}

func idRank(id string) int {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return 3
	case strings.HasPrefix(id, "GHSA-"):
		return 2
	}
	return 1
}

// FixedIn returns the version that fixes this advisory on the branch the
// installed version sits on. Advisories carry one range per major branch, so
// the lowest fix strictly above the installed version is the relevant one.
// An empty result means no fix exists for that branch.
func FixedIn(v Vuln, pkg finding.Package) string {
	best := ""
	for _, a := range v.Affected {
		if a.Package.Name != pkg.Name {
			continue
		}
		best = lowestFixAbove(a.Ranges, pkg.Version, best)
	}
	return best
}

func lowestFixAbove(ranges []Range, installed, best string) string {
	for _, r := range ranges {
		for _, e := range r.Events {
			best = preferFix(e.Fixed, installed, best)
		}
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

// Severity resolves an advisory's severity, preferring the source database's
// own rating and exposing the CVSS vector when one is present.
func Severity(v Vuln) (finding.Severity, string) {
	vector := ""
	for _, s := range v.Severity {
		if strings.HasPrefix(s.Type, "CVSS") {
			vector = s.Score
			break
		}
	}
	return finding.ParseSeverity(strings.ToUpper(v.DatabaseSpecific.Severity)), vector
}
