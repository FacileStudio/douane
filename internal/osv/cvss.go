package osv

import (
	"math"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

var (
	cvssAV  = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	cvssAC  = map[string]float64{"L": 0.77, "H": 0.44}
	cvssUI  = map[string]float64{"N": 0.85, "R": 0.62}
	cvssCIA = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	cvssPRU = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	cvssPRC = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
)

var cvssRequired = []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}

// cvss31Severity rates a CVSS v3.1 vector by its base score, using the
// qualitative bands from the specification. v2 and v4 vectors return unknown:
// v4's base score is a MacroVector lookup table rather than a formula, and no
// closure measured against the live API carried one without also carrying a
// label, so computing it would buy nothing douane does not already have.
func cvss31Severity(vector string) finding.Severity {
	score, ok := cvss31Score(vector)
	switch {
	case !ok:
		return finding.SevUnknown
	case score >= 9:
		return finding.SevCritical
	case score >= 7:
		return finding.SevHigh
	case score >= 4:
		return finding.SevMedium
	case score > 0:
		return finding.SevLow
	}
	return finding.SevUnknown
}

// cvss31Score computes the CVSS v3.1 base score, from the formula in section
// 7.1 of the specification. The scope-changed branch is where v3.1 differs from
// v3.0, which is why the version prefix is checked rather than assumed.
func cvss31Score(vector string) (float64, bool) {
	b, ok := cvssParse(vector)
	if !ok {
		return 0, false
	}
	iss := 1 - (1-b.conf)*(1-b.integ)*(1-b.avail)
	impact := 6.42 * iss
	if b.changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}
	score := impact + 8.22*b.av*b.ac*b.pr*b.ui
	if b.changed {
		score *= 1.08
	}
	return cvssRoundUp(math.Min(score, 10)), true
}

// cvssBase is one parsed vector. Privileges Required is read from a different
// table depending on scope, which is the only metric whose weight depends on
// another.
type cvssBase struct {
	av, ac, pr, ui     float64
	conf, integ, avail float64
	changed            bool
}

func cvssParse(vector string) (cvssBase, bool) {
	m := cvssMetrics(vector)
	if m == nil {
		return cvssBase{}, false
	}
	b := cvssBase{changed: m["S"] == "C"}
	pr := cvssPRU
	if b.changed {
		pr = cvssPRC
	}
	var found [7]bool
	b.av, found[0] = cvssAV[m["AV"]]
	b.ac, found[1] = cvssAC[m["AC"]]
	b.pr, found[2] = pr[m["PR"]]
	b.ui, found[3] = cvssUI[m["UI"]]
	b.conf, found[4] = cvssCIA[m["C"]]
	b.integ, found[5] = cvssCIA[m["I"]]
	b.avail, found[6] = cvssCIA[m["A"]]
	for _, ok := range found {
		if !ok {
			return cvssBase{}, false
		}
	}
	return b, true
}

func cvssMetrics(vector string) map[string]string {
	if !strings.HasPrefix(vector, "CVSS:3.") {
		return nil
	}
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		if k, v, ok := strings.Cut(part, ":"); ok {
			m[k] = v
		}
	}
	for _, k := range cvssRequired {
		if _, ok := m[k]; !ok {
			return nil
		}
	}
	return m
}

// cvssRoundUp is v3.1's own rounding: always up to one decimal, computed on
// integers because the float form of the same rule rounds 8.6 down to 8.5.
func cvssRoundUp(score float64) float64 {
	i := int64(math.Round(score * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}
