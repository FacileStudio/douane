package output

import (
	"fmt"
	"io"
)

// tally is what the closing line of a fleet run counts: the repositories that
// held nothing, the ones that could not be read at all, and the ones douane
// only partly determined.
type tally struct{ clear, failed, incomplete int }

// writeSweepSummary closes a fleet run: one row per repository holding
// findings, then the totals.
func writeSweepSummary(w io.Writer, s Sweep, held, packages, kev int) {
	t := writeRepoRows(w, s.Repos)
	fmt.Fprintf(w, "\n%d held out of %d packages across %d repos", held, packages, len(s.Repos))
	writeSweepTail(w, kev, t)
}

func writeRepoRows(w io.Writer, repos []Report) tally {
	var t tally
	width := nameWidth(repos)
	for _, r := range repos {
		if r.Failed {
			t.failed++
		}
		if !r.Complete() {
			t.incomplete++
		}
		if len(r.Findings) == 0 {
			t.clear++
			continue
		}
		fmt.Fprintf(w, "  %-*s  %6d findings  %6d packages\n", width, r.Name,
			len(r.Findings), r.Packages)
	}
	return t
}

func nameWidth(repos []Report) int {
	width := 0
	for _, r := range repos {
		if len(r.Findings) > 0 && len(r.Name) > width {
			width = len(r.Name)
		}
	}
	return width
}

func writeSweepTail(w io.Writer, kev int, t tally) {
	if t.clear > 0 {
		fmt.Fprintf(w, " — %d clear", t.clear)
	}
	if kev > 0 {
		fmt.Fprintf(w, " — %d known exploited", kev)
	}
	if t.failed > 0 {
		fmt.Fprintf(w, " — %d could not be read", t.failed)
	}
	if t.incomplete > 0 {
		fmt.Fprintf(w, " — %d incomplete", t.incomplete)
	}
	fmt.Fprintln(w)
}

func sweepTotals(s Sweep) (held, packages, kev int) {
	for _, r := range s.Repos {
		held += len(r.Findings)
		packages += r.Packages
		for _, f := range r.Findings {
			if f.Exploit.KEV {
				kev++
			}
		}
	}
	return held, packages, kev
}

// anyNote reports whether the run has anything to say beyond its findings. A
// fleet that held nothing still prints when a repository left a gap: "clear"
// would be a claim douane cannot make.
func anyNote(s Sweep) bool {
	for _, r := range s.Repos {
		if len(r.Warnings) > 0 || len(r.Gaps) > 0 {
			return true
		}
	}
	return len(s.Warnings) > 0 || len(s.Gaps) > 0
}
