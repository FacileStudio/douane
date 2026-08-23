package osv

import (
	"sort"
	"strings"
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
