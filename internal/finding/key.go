package finding

import (
	"slices"
	"strings"
)

// nativePrefixes are the ecosystem databases whose identifier is the record's
// own primary. They rank below CVE and GHSA because a CVE or GHSA twin is the
// name the same flaw carries across ecosystems.
var nativePrefixes = []string{"GO-", "RUSTSEC-", "PYSEC-", "OSV-", "MAL-"}

// nameRank orders a flaw's names by how stable a key they make. A CVE is the
// name every database converges on; a GHSA is the next most shared; an
// ecosystem's own identifier follows; anything else, such as a downstream
// distributor's BIT- copy, is the last resort. Ranking rather than sorting
// keeps a key still when OSV adds a low-ranked alias that sorts first.
func nameRank(name string) int {
	switch {
	case strings.HasPrefix(name, "CVE-"):
		return 3
	case strings.HasPrefix(name, "GHSA-"):
		return 2
	case slices.ContainsFunc(nativePrefixes, func(p string) bool { return strings.HasPrefix(name, p) }):
		return 1
	}
	return 0
}

// Names lists every identifier the flaw goes by, sorted and without repeats or
// blanks.
func (f Finding) Names() []string {
	names := []string{}
	for _, name := range append([]string{f.ID}, f.Aliases...) {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// KeyName is the name a finding is keyed under: the highest-ranked of its
// names, the smallest within that rank. It moves only when a better-ranked
// name appears, which in practice means once, when a CVE is assigned.
func (f Finding) KeyName() string {
	best := ""
	for _, name := range f.Names() {
		if best == "" || nameRank(name) > nameRank(best) {
			best = name
		}
	}
	return best
}

// Key identifies a finding across sweeps. It does not follow the identifier
// douane chose to report, because that choice moves: OSV answering 404 for a
// CVE twin on one run and a record on the next flips the report between the
// CVE and its GHSA alias, and a key that followed it read every flip as one
// finding resolved and one new.
func (f Finding) Key() string {
	return f.KeyAs(f.KeyName())
}

// KeyAs is the key this finding would carry if it were filed under name. It
// reads history written under an earlier keying rule.
func (f Finding) KeyAs(name string) string {
	return f.Ecosystem + "|" + f.Package + "|" + f.Installed + "|" + name
}
