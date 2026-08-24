package output

import (
	"io"
	"sort"

	"github.com/FacileStudio/douane/internal/finding"
)

// Sweep is one fleet run: every repo under a root, each already ranked. As
// with Report, json.go owns the shape this leaves in.
type Sweep struct {
	Root     string        `json:"root"`
	Repos    []Report      `json:"repos"`
	Gaps     []finding.Gap `json:"gaps,omitempty"`
	Warnings []string      `json:"warnings,omitempty"`
}

// AllGaps returns every gap in the run, the fleet's own and each repo's.
func (s Sweep) AllGaps() []finding.Gap {
	out := append([]finding.Gap{}, s.Gaps...)
	for _, r := range s.Repos {
		out = append(out, r.Gaps...)
	}
	return out
}

// Complete reports whether the whole fleet was determined. One repository
// douane could not read is enough to make the answer for the fleet partial.
func (s Sweep) Complete() bool { return len(s.AllGaps()) == 0 }

// WriteSweep renders a fleet run in the given format, everything on w.
func WriteSweep(w io.Writer, f Format, s Sweep) error { return WriteSweepTo(w, w, f, LayoutFix, s) }

// WriteSweepTo renders a fleet run, data on out and notes on errw. See WriteTo
// for why the two streams are worth separating.
func WriteSweepTo(out, errw io.Writer, f Format, l Layout, s Sweep) error {
	if f == JSON || f == Line {
		if err := writeSweepNotes(errw, s); err != nil {
			return err
		}
	}
	switch f {
	case JSON:
		return encodeJSON(out, s)
	case Line:
		return writeSweepLine(out, s, l)
	default:
		return writeSweepText(out, s, l)
	}
}

// SortRepos orders repos by their worst finding, so the first group printed is
// the one to open first. Repos with nothing held sort last.
func SortRepos(repos []Report) {
	sort.SliceStable(repos, func(i, j int) bool {
		a, b := repos[i], repos[j]
		if len(a.Findings) == 0 || len(b.Findings) == 0 {
			return len(a.Findings) > len(b.Findings)
		}
		return finding.Less(a.Findings[0], b.Findings[0])
	})
}
