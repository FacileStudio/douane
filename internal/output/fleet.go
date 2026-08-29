package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

func writeSweepLine(w io.Writer, s Sweep, l Layout) error {
	if l == LayoutFinding {
		return sweepFlatLines(w, s)
	}
	return sweepFixLines(w, s)
}

func sweepFixLines(w io.Writer, s Sweep) error {
	for _, g := range fleetGroups(s) {
		fix := g.FixedIn
		if fix == "" {
			fix = "no-fix"
		}
		worst := g.WorstFinding()
		if _, err := fmt.Fprintf(w,
			"%s:%s@%s: %d finding%s in %d target%s: %s: worst=%s [epss=%.4f kev=%t fix=%s targets=%s]\n",
			g.Ecosystem, g.Package, fix, g.Count, plural(g.Count), len(g.Targets),
			plural(len(g.Targets)), strings.ToLower(g.Worst.String()), worst.ID,
			worst.Exploit.EPSS, g.KEV, fix, capAt(g.Targets, 5)); err != nil {
			return err
		}
	}
	return nil
}

func writeSweepText(w io.Writer, s Sweep, l Layout) error {
	st, gl := newStyle(w), glyphsFor(w)
	writeNotesText(w, st, s.Gaps, s.Warnings)
	t := totalsOf(s)
	if t.held == 0 && !anyNote(s) {
		fmt.Fprintf(w, "%s — %d repos, %d packages, nothing held\n",
			st.fix("clear"), len(s.Repos), t.packages)
		return nil
	}
	if l == LayoutFix && t.held > 0 {
		writeSweepFixText(w, st, gl, s, t)
		return nil
	}
	writeSweepRepoText(w, st, gl, s)
	return nil
}

func writeSweepFixText(w io.Writer, st style, gl glyphs, s Sweep, t fleetTotals) {
	groups := fleetGroups(s)
	verb := "clear"
	if len(groups) == 1 {
		verb = "clears"
	}
	fmt.Fprintf(w, "%d findings across %d repos, %d %s %s them\n\n",
		t.held, repoCount(s), len(groups), fixes(len(groups)), verb)
	for _, g := range groups {
		writeGroup(w, st, gl, g)
	}
	writeRepoNotes(w, st, s)
	writeSweepSummary(w, st, gl, s, t, len(groups))
}

func writeSweepRepoText(w io.Writer, st style, gl glyphs, s Sweep) {
	for _, r := range s.Repos {
		if len(r.Findings) == 0 && len(r.Warnings) == 0 && len(r.Gaps) == 0 {
			continue
		}
		writeRepo(w, st, gl, r)
	}
	writeSweepSummary(w, st, gl, s, totalsOf(s), 0)
}

// fleetGroups groups every finding in the run by the fix that clears it,
// attributing each to its repository name rather than the lockfile path a
// single scan would show.
func fleetGroups(s Sweep) []finding.Group {
	newSet := map[string]bool{}
	var fs []finding.Finding
	for _, r := range s.Repos {
		for k := range r.New {
			newSet[k] = true
		}
		for _, f := range r.Findings {
			f.Target = r.Name
			fs = append(fs, f)
		}
	}
	return finding.Groups(fs, func(f finding.Finding) bool { return newSet[f.Key()] })
}

// writeRepoNotes keeps the grouped view honest: a fix can collapse the
// findings, but a repo the scanner could not fully read must still say so, by
// name, or the group line reads as more certainty than the sweep earned.
func writeRepoNotes(w io.Writer, st style, s Sweep) {
	for _, r := range s.Repos {
		if len(r.Gaps) == 0 && len(r.Warnings) == 0 {
			continue
		}
		fmt.Fprintf(w, "%s:\n", st.bold(r.Name))
		writeNotesText(w, st, r.Gaps, r.Warnings)
	}
}
func writeRepo(w io.Writer, st style, gl glyphs, r Report) {
	fmt.Fprintf(w, "%s — %d held out of %d packages\n\n",
		st.bold(r.Name), len(r.Findings), r.Packages)
	writeNotesText(w, st, r.Gaps, r.Warnings)
	for _, f := range r.Findings {
		writeFinding(w, st, gl, f, r.New[f.Key()])
	}
}
