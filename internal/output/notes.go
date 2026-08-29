package output

import (
	"fmt"
	"io"

	"github.com/FacileStudio/douane/internal/finding"
)

// notes are the two things douane says about a run that are not findings: what
// it could not determine, and what a reader needs to know to read the rest.
// Both come first, everywhere. A gap changes how every line under it should be
// read — "the KEV feed was down" is not a footnote to a ranking that used it —
// and a reader who stops halfway down a long list must not be the one who
// misses it.

// writeNotes renders the machine-readable form, tagging every line with prefix
// so a fleet run says which repository a note came from. Gaps carry their kind,
// so "this lockfile would not parse" stays distinguishable from "OSV refused".
func writeNotes(w io.Writer, prefix string, gaps []finding.Gap, warnings []string) error {
	for _, g := range finding.Gaps(gaps) {
		if _, err := fmt.Fprintf(w, "douane: gap: %s%s\n", prefix, g); err != nil {
			return err
		}
	}
	for _, warn := range warnings {
		if _, err := fmt.Fprintf(w, "douane: warning: %s%s\n", prefix, warn); err != nil {
			return err
		}
	}
	return nil
}

// writeNotesText renders the human form. A gap is marked with a question, not
// a bang: it is an unanswered question, and nothing about it should read like
// a finding.
func writeNotesText(w io.Writer, th theme, gaps []finding.Gap, warnings []string) {
	for _, g := range finding.Gaps(gaps) {
		fmt.Fprintf(w, "  %s %s\n", th.warn("?"), th.dim(g))
	}
	for _, warn := range warnings {
		fmt.Fprintf(w, "  %s %s\n", th.warn("!"), th.dim(warn))
	}
	if len(gaps)+len(warnings) > 0 {
		fmt.Fprintln(w)
	}
}

// writeSweepNotes renders a whole fleet run's notes, the run's own first and
// then each repository's, so the stream a parser ignores still reads in order.
func writeSweepNotes(w io.Writer, s Sweep) error {
	if err := writeNotes(w, "", s.Gaps, s.Warnings); err != nil {
		return err
	}
	for _, r := range s.Repos {
		if err := writeNotes(w, r.Name+": ", r.Gaps, r.Warnings); err != nil {
			return err
		}
	}
	return nil
}
