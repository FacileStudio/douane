package output

import (
	"fmt"
	"io"
)

// writeSweepSummary closes a fleet run: one row per repository holding
// findings, then the totals.
func writeSweepSummary(w io.Writer, s Sweep, held, packages, kev int) {
	clear, failed := writeRepoRows(w, s.Repos)
	fmt.Fprintf(w, "\n%d held out of %d packages across %d repos", held, packages, len(s.Repos))
	writeSweepTail(w, kev, clear, failed)
}

func writeRepoRows(w io.Writer, repos []Report) (clear, failed int) {
	width := nameWidth(repos)
	for _, r := range repos {
		if r.Failed {
			failed++
		}
		if len(r.Findings) == 0 {
			clear++
			continue
		}
		fmt.Fprintf(w, "  %-*s  %6d findings  %6d packages\n", width, r.Name,
			len(r.Findings), r.Packages)
	}
	return clear, failed
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

func writeSweepTail(w io.Writer, kev, clear, failed int) {
	if clear > 0 {
		fmt.Fprintf(w, " — %d clear", clear)
	}
	if kev > 0 {
		fmt.Fprintf(w, " — %d known exploited", kev)
	}
	if failed > 0 {
		fmt.Fprintf(w, " — %d could not be read", failed)
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

func anyWarning(s Sweep) bool {
	for _, r := range s.Repos {
		if len(r.Warnings) > 0 {
			return true
		}
	}
	return len(s.Warnings) > 0
}
