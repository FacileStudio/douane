package output

import (
	"fmt"
	"io"
)

// tally is what the closing line of a fleet run counts: the repositories that
// held nothing, the ones that could not be read at all, and the ones douane
// only partly determined.
type tally struct{ clear, failed, incomplete int }

// fleetTotals is the three numbers every closing line needs.
type fleetTotals struct{ held, packages, kev int }

// writeSweepSummary closes a fleet run: one row per repository holding
// findings, then the totals. fixes is the grouped view's action count, zero in
// flat mode.
func writeSweepSummary(w io.Writer, st style, s Sweep, t fleetTotals, fixes int) {
	tally := writeRepoRows(w, st, s.Repos)
	fmt.Fprintf(w, "\n%d held out of %d packages across %d repos",
		t.held, t.packages, len(s.Repos))
	if fixes > 0 {
		fmt.Fprintf(w, " in %d fix%s", fixes, plural(fixes))
	}
	writeSweepTail(w, st, t.kev, tally)
}

func writeRepoRows(w io.Writer, st style, repos []Report) tally {
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
		fmt.Fprintf(w, "  %s  %s\n", st.bold(fmt.Sprintf("%-*s", width, r.Name)),
			st.dim(fmt.Sprintf("%6d findings  %6d packages", len(r.Findings), r.Packages)))
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

func writeSweepTail(w io.Writer, st style, kev int, t tally) {
	if t.clear > 0 {
		fmt.Fprintf(w, " — %s", st.fix(fmt.Sprintf("%d clear", t.clear)))
	}
	if kev > 0 {
		fmt.Fprintf(w, " — %s", st.alarm(fmt.Sprintf("%d known exploited", kev)))
	}
	if t.failed > 0 {
		fmt.Fprintf(w, " — %s", st.warn(fmt.Sprintf("%d could not be read", t.failed)))
	}
	if t.incomplete > 0 {
		fmt.Fprintf(w, " — %s", st.warn(fmt.Sprintf("%d incomplete", t.incomplete)))
	}
	fmt.Fprintln(w)
}

func totalsOf(s Sweep) (t fleetTotals) {
	for _, r := range s.Repos {
		t.held += len(r.Findings)
		t.packages += r.Packages
		for _, f := range r.Findings {
			if f.Exploit.KEV {
				t.kev++
			}
		}
	}
	return t
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
