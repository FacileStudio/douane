package permit

import (
	"fmt"
	"slices"
	"time"

	"github.com/FacileStudio/douane/internal/finding"
)

// Match pairs a finding with the permit that names it. Gaps are the gaps that
// existed only because of this finding, which the permit covers along with it.
type Match struct {
	Finding finding.Finding
	Permit  Permit
	Gaps    []finding.Gap
}

// Outcome is one report's findings after its permits were applied. Kept is
// what still reaches the output and the exit code, expired matches included:
// a lapsed permit returns its finding rather than dropping it. Unused lists
// the lapsed permits that returned no finding either, because nothing matches
// them any more or a valid permit for the same finding took over.
type Outcome struct {
	Kept      []finding.Finding
	Permitted []Match
	Expired   []Match
	Unused    []Permit
}

// Covers reports whether p names f: by any of the finding's names, and by its
// package when the permit gives one.
func (p Permit) Covers(f finding.Finding) bool {
	if p.Package != "" && p.Package != f.Package {
		return false
	}
	return slices.Contains(f.Names(), p.ID)
}

// Apply sorts findings into kept, permitted and expired. When several permits
// name one finding, a valid one wins over a lapsed one, so renewing a permit by
// adding a fresh entry works without deleting the old one first.
func Apply(fs []finding.Finding, permits []Permit, today time.Time) Outcome {
	var out Outcome
	used := make([]bool, len(permits))
	for _, f := range fs {
		i := pick(f, permits, today)
		switch {
		case i < 0:
			out.Kept = append(out.Kept, f)
			continue
		case permits[i].Lapsed(today):
			out.Kept = append(out.Kept, f)
			out.Expired = append(out.Expired, Match{Finding: f, Permit: permits[i]})
		default:
			out.Permitted = append(out.Permitted, Match{Finding: f, Permit: permits[i]})
		}
		used[i] = true
	}
	for i, p := range permits {
		if !used[i] && p.Lapsed(today) {
			out.Unused = append(out.Unused, p)
		}
	}
	return out
}

func pick(f finding.Finding, permits []Permit, today time.Time) int {
	found := -1
	for i, p := range permits {
		if !p.Covers(f) {
			continue
		}
		if !p.Lapsed(today) {
			return i
		}
		if found < 0 {
			found = i
		}
	}
	return found
}

// Expiring lists the permits still valid on today that lapse within Soon.
func Expiring(permits []Permit, today time.Time) []Permit {
	var out []Permit
	for _, p := range permits {
		if !p.Lapsed(today) && p.Expires.Sub(today) <= Soon {
			out = append(out, p)
		}
	}
	return out
}

// Notes are the lines a run prints about its permits, all of them meant for
// stderr: every lapsed permit that returned a finding, every lapsed permit
// left with nothing to do, and every permit about to lapse.
func Notes(out Outcome, permits []Permit, today time.Time) []string {
	var notes []string
	for _, m := range out.Expired {
		notes = append(notes, fmt.Sprintf("EXPIRED PERMIT: %s on %s lapsed %s, the finding is back (%s:%d)",
			m.Permit.ID, m.Finding.Package, day(m.Permit.Expires), FileName, m.Permit.Line))
	}
	for _, p := range out.Unused {
		notes = append(notes, fmt.Sprintf("permit %s lapsed %s and suppresses nothing, remove it (%s:%d)",
			p.ID, day(p.Expires), FileName, p.Line))
	}
	for _, p := range Expiring(permits, today) {
		days := int(p.Expires.Sub(today).Hours() / 24)
		notes = append(notes, fmt.Sprintf("permit %s expires %s, %s (%s:%d)",
			p.ID, day(p.Expires), when(days), FileName, p.Line))
	}
	return notes
}

func day(t time.Time) string { return t.Format(dateLayout) }

func when(days int) string {
	switch days {
	case 0:
		return "today"
	case 1:
		return "tomorrow"
	}
	return fmt.Sprintf("in %d days", days)
}
