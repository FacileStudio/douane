package osv

import (
	"slices"
	"strings"
)

// Informational returns the informational category of an advisory, or "" when
// it is a real vulnerability. The RUSTSEC database marks a defect that is not
// an exploitable flaw — an unmaintained crate, an unsound guarantee, a notice —
// on the affected entry's database_specific.informational field, and GitHub
// refuses to twin these into GHSAs, so the marker travels alone and reading it
// needs no alias closure.
//
// Distinct categories across affected entries are joined so one report line
// can carry both an "unmaintained" and an "unsound" label without losing
// either.
func Informational(v Vuln) string {
	var out []string
	for _, a := range v.Affected {
		c := a.DatabaseSpecific.Informational
		if c == "" || slices.Contains(out, c) {
			continue
		}
		out = append(out, c)
	}
	return strings.Join(out, ",")
}

// IsInformational reports whether an advisory is an informational defect
// rather than a scored vulnerability. Its presence is the category value it
// carries; an advisory either has the marker or it does not.
func IsInformational(v Vuln) bool { return Informational(v) != "" }
