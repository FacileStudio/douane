package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

func writeText(w io.Writer, r Report, l Layout) error {
	st := newStyle(w)
	writeNotesText(w, st, r.Gaps, r.Warnings)
	if len(r.Findings) == 0 {
		return writeNothingHeld(w, st, r)
	}
	if l == LayoutFinding {
		for _, f := range r.Findings {
			writeFinding(w, st, f, r.New[f.Key()])
		}
		writeSummary(w, st, r, 0)
		return nil
	}
	groups := finding.Groups(r.Findings, isNewFn(r))
	for _, g := range groups {
		writeGroup(w, st, g)
	}
	writeSummary(w, st, r, len(groups))
	return nil
}

// writeNothingHeld closes a scan that held nothing. It says clear only when
// douane determined the whole answer: an incomplete scan that found nothing
// has not established that there is nothing to find.
func writeNothingHeld(w io.Writer, st style, r Report) error {
	if !r.Complete() {
		_, err := fmt.Fprintf(w, "%s — %d packages, nothing held, %d unanswered\n",
			st.warn("incomplete"), r.Packages, len(r.Gaps))
		return err
	}
	_, err := fmt.Fprintf(w, "%s — %d packages, nothing held\n", st.fix("clear"), r.Packages)
	return err
}

func writeFinding(w io.Writer, st style, f finding.Finding, isNew bool) {
	fmt.Fprintf(w, "%s %s %s@%s%s\n",
		st.bold(fmt.Sprintf("%-9s", f.Severity)), st.dim(f.ID),
		st.bold(f.Package), f.Installed, badge(st, f, isNew))
	fmt.Fprintf(w, "          %s · %s · %s · %s\n",
		epssLabel(st, f), fixLabel(st, f), st.dim(f.Ecosystem), st.dim(f.Target))
	if f.Summary != "" {
		fmt.Fprintf(w, "          %s\n", st.dim(f.Summary))
	}
	fmt.Fprintln(w)
}

func badge(st style, f finding.Finding, isNew bool) string {
	flags := []string{}
	if f.Exploit.KEV {
		flags = append(flags, st.alarm("KEV"))
	}
	if f.Exploit.Ransomware {
		flags = append(flags, st.alarm("RANSOMWARE"))
	}
	if isNew {
		flags = append(flags, st.warn("NEW"))
	}
	if !f.HasFix() {
		flags = append(flags, st.warn("NO FIX"))
	}
	if len(flags) == 0 {
		return ""
	}
	return "  [" + strings.Join(flags, " ") + "]"
}

func epssLabel(st style, f finding.Finding) string {
	if !f.Exploit.EPSSKnown {
		return st.dim("epss —")
	}
	label := fmt.Sprintf("epss %.2f%%", f.Exploit.EPSS*100)
	if f.Exploit.EPSS >= epssNotable {
		return st.warn(label)
	}
	return st.dim(label)
}

func fixLabel(st style, f finding.Finding) string {
	if !f.HasFix() {
		return st.warn("no fix available")
	}
	return st.dim("fix ") + st.fix(f.FixedIn)
}

// writeSummary closes a scan. fixes is how many actions the grouped view
// reduced the findings to; zero means flat mode, which has nothing to add.
func writeSummary(w io.Writer, st style, r Report, fixes int) {
	kev := 0
	for _, f := range r.Findings {
		if f.Exploit.KEV {
			kev++
		}
	}
	fmt.Fprintf(w, "%d held out of %d packages", len(r.Findings), r.Packages)
	if fixes > 0 {
		fmt.Fprintf(w, " in %d fix%s", fixes, plural(fixes))
	}
	if kev > 0 {
		fmt.Fprintf(w, " — %s", st.alarm(fmt.Sprintf("%d known exploited", kev)))
	}
	fmt.Fprintln(w)
}
