package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/FacileStudio/douane/internal/finding"
)

// Sweep is one fleet run: every repo under a root, each already ranked.
type Sweep struct {
	Root     string   `json:"root"`
	Repos    []Report `json:"repos"`
	Warnings []string `json:"warnings,omitempty"`
}

// WriteSweep renders a fleet run in the given format.
func WriteSweep(w io.Writer, f Format, s Sweep) error {
	switch f {
	case JSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(s)
	case Line:
		return writeSweepLine(w, s)
	default:
		return writeSweepText(w, s)
	}
}

func writeSweepLine(w io.Writer, s Sweep) error {
	for _, r := range s.Repos {
		if err := writeLinePrefixed(w, r.Name+": ", r); err != nil {
			return err
		}
	}
	for _, warn := range s.Warnings {
		if _, err := fmt.Fprintf(w, "douane: warning: %s\n", warn); err != nil {
			return err
		}
	}
	return nil
}

func writeSweepText(w io.Writer, s Sweep) error {
	writeWarnings(w, s.Warnings)
	held, packages, kev := sweepTotals(s)
	if held == 0 && !anyWarning(s) {
		fmt.Fprintf(w, "clear — %d repos, %d packages, nothing held\n", len(s.Repos), packages)
		return nil
	}
	for _, r := range s.Repos {
		if len(r.Findings) == 0 && len(r.Warnings) == 0 {
			continue
		}
		writeRepo(w, r)
	}
	writeSweepSummary(w, s, held, packages, kev)
	return nil
}

func writeRepo(w io.Writer, r Report) {
	fmt.Fprintf(w, "%s — %d held out of %d packages\n\n", r.Name, len(r.Findings), r.Packages)
	writeWarnings(w, r.Warnings)
	for _, f := range r.Findings {
		writeFinding(w, f, r.New[f.Key()])
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
