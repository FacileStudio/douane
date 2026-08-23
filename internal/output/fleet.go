package output

import (
	"fmt"
	"io"
)

func writeSweepLine(w io.Writer, s Sweep) error {
	for _, r := range s.Repos {
		if err := writeLinePrefixed(w, r.Name+": ", r); err != nil {
			return err
		}
	}
	return nil
}

func writeSweepText(w io.Writer, s Sweep) error {
	writeNotesText(w, s.Gaps, s.Warnings)
	held, packages, kev := sweepTotals(s)
	if held == 0 && !anyNote(s) {
		fmt.Fprintf(w, "clear — %d repos, %d packages, nothing held\n", len(s.Repos), packages)
		return nil
	}
	for _, r := range s.Repos {
		if len(r.Findings) == 0 && len(r.Warnings) == 0 && len(r.Gaps) == 0 {
			continue
		}
		writeRepo(w, r)
	}
	writeSweepSummary(w, s, held, packages, kev)
	return nil
}

func writeRepo(w io.Writer, r Report) {
	fmt.Fprintf(w, "%s — %d held out of %d packages\n\n", r.Name, len(r.Findings), r.Packages)
	writeNotesText(w, r.Gaps, r.Warnings)
	for _, f := range r.Findings {
		writeFinding(w, f, r.New[f.Key()])
	}
}
