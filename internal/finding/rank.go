package finding

import "sort"

// EPSS bands. FIRST publishes no threshold and explicitly disowns the 0.1 one
// everybody quotes, but it does publish two effort anchors: acting at 0.04 is
// about the effort a CVSS-Critical policy spends, and 0.008 about what a
// CVSS-High policy spends.
const (
	epssHighEffort = 0.008
	epssCritEffort = 0.04
)

// epssTier bands a finding by exploitation likelihood. Bands rather than the
// raw score, because EPSS below the noise floor is not a signal: comparing
// 0.0004 against 0.0003 as though it were one is what buried unscored findings
// under scored ones. A finding EPSS has no score for lands in the bottom band
// with the noise, which is the same claim — no evidence of likelihood — rather
// than being treated as a measured zero.
func epssTier(e Exploit) int {
	if !e.EPSSKnown {
		return 0
	}
	switch {
	case e.EPSS >= epssCritEffort:
		return 2
	case e.EPSS >= epssHighEffort:
		return 1
	}
	return 0
}

// Rank sorts findings by what should be acted on first: known-exploited, then
// likelihood of exploitation, then severity, then a stable tiebreak.
func Rank(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool { return Less(fs[i], fs[j]) })
}

// Less reports whether a should be acted on before b. It is what Rank sorts
// by, exported so a fleet report can order repos by their worst finding
// without a second, quietly different, notion of "worst".
//
// The order is lexicographic over KEV, then the EPSS band, then severity, then
// the raw score, then a stable tiebreak. Every axis is totally ordered, which
// is what keeps the comparison transitive: an earlier version compared EPSS
// only when both scores were known and fell through to severity otherwise,
// which yields a < c < b and b < a for three findings and leaves sort.Stable
// free to return any order at all.
//
// KEV outranks everything because CISA's own guidance is precedence, not
// arithmetic: a vulnerability on the catalogue is treated as actively
// exploited regardless of its score.
func Less(a, b Finding) bool {
	at, bt := epssTier(a.Exploit), epssTier(b.Exploit)
	switch {
	case a.Exploit.KEV != b.Exploit.KEV:
		return a.Exploit.KEV
	case at != bt:
		return at > bt
	case a.Severity != b.Severity:
		return a.Severity > b.Severity
	case a.Exploit.EPSS != b.Exploit.EPSS:
		return a.Exploit.EPSS > b.Exploit.EPSS
	case a.Package != b.Package:
		return a.Package < b.Package
	}
	return a.ID < b.ID
}
