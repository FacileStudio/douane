package cli

import (
	"slices"

	"github.com/FacileStudio/douane/internal/finding"
)

// indexIDs keys each queried package's advisory ids by the package, skipping
// packages OSV returned nothing for.
func indexIDs(pkgs []finding.Package, idx [][]string) map[string][]string {
	ids := map[string][]string{}
	for i, list := range idx {
		if len(list) > 0 && i < len(pkgs) {
			ids[pkgKey(pkgs[i])] = list
		}
	}
	return ids
}

// flatIDs lists every advisory id the fleet asked about, sorted so the fetch
// order does not depend on map iteration.
func flatIDs(ids map[string][]string) []string {
	var flat []string
	for _, list := range ids {
		flat = append(flat, list...)
	}
	slices.Sort(flat)
	return slices.Compact(flat)
}

// repoGaps picks the fleet gaps one repository inherits: those that can hide
// findings, as Gap.HidesFindings classifies them. A failed query cannot
// be pinned on a package with certainty, so every repository with packages
// takes it; a failed advisory fetch names its advisory, so only repositories
// whose packages asked for it do.
func repoGaps(pkgs []finding.Package, ids map[string][]string, query, fetch []finding.Gap) []finding.Gap {
	if len(pkgs) == 0 {
		return nil
	}
	asked := askedIDs(pkgs, ids)
	var out []finding.Gap
	for _, g := range append(slices.Clone(query), fetch...) {
		if !g.HidesFindings() {
			continue
		}
		if g.Kind == finding.GapUnresolved && !asked[g.Subject] {
			continue
		}
		out = append(out, g)
	}
	return out
}

func askedIDs(pkgs []finding.Package, ids map[string][]string) map[string]bool {
	asked := map[string]bool{}
	for _, p := range pkgs {
		for _, id := range ids[pkgKey(p)] {
			asked[id] = true
		}
	}
	return asked
}
