package osv

import (
	"sort"
	"strings"
)

// Canonical picks the identifier a vulnerability should be reported under,
// preferring a CVE so the same flaw carries one name across ecosystems, and
// returns the remaining identifiers as aliases.
//
// An id proven not to exist can never win the ranking. An alias list names
// twins the source database does not necessarily carry, and douane was
// promoting them unchecked: `github.com/klauspost/compress@1.17.11` reported as
// `GHSA-259r-337f-4rfw`, which 404s on OSV and on github.com/advisories alike,
// while `GO-2026-5841`, the id the query returned, sat in the aliases.
//
// Absent means asked and refused, never merely unfetched. Most CVE twins are
// never requested, because a closure that already rates itself needs no second
// record, and they resolve perfectly well at nvd.nist.gov whether or not OSV
// carries them. Demanding a held record instead would demote almost every npm
// finding from its CVE to its GHSA and rewrite the history the store keys on
// that id, to fix eleven findings.
func Canonical(v Vuln, absent map[string]bool) (string, []string) {
	all := append([]string{v.ID}, v.Aliases...)
	sort.Strings(all)

	best, rank := v.ID, idRank(v.ID)
	for _, id := range all {
		if absent[id] {
			continue
		}
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
