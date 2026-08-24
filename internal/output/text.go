package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

func writeText(w io.Writer, r Report, l Layout) error {
	writeNotesText(w, r.Gaps, r.Warnings)
	if len(r.Findings) == 0 {
		return writeNothingHeld(w, r)
	}
	if l == LayoutFinding {
		for _, f := range r.Findings {
			writeFinding(w, f, r.New[f.Key()])
		}
		writeSummary(w, r, 0)
		return nil
	}
	groups := finding.Groups(r.Findings, isNewFn(r))
	for _, g := range groups {
		writeGroup(w, g)
	}
	writeSummary(w, r, len(groups))
	return nil
}

// writeNothingHeld closes a scan that held nothing. It says clear only when
// douane determined the whole answer: an incomplete scan that found nothing
// has not established that there is nothing to find.
func writeNothingHeld(w io.Writer, r Report) error {
	if !r.Complete() {
		_, err := fmt.Fprintf(w, "incomplete — %d packages, nothing held, %d unanswered\n",
			r.Packages, len(r.Gaps))
		return err
	}
	_, err := fmt.Fprintf(w, "clear — %d packages, nothing held\n", r.Packages)
	return err
}

func writeFinding(w io.Writer, f finding.Finding, isNew bool) {
	fmt.Fprintf(w, "%-9s %s %s@%s%s\n",
		f.Severity, f.ID, f.Package, f.Installed, badge(f, isNew))
	fmt.Fprintf(w, "          %s · %s · %s · %s\n",
		epssLabel(f), fixLabel(f), f.Ecosystem, f.Target)
	if f.Summary != "" {
		fmt.Fprintf(w, "          %s\n", f.Summary)
	}
	fmt.Fprintln(w)
}

func badge(f finding.Finding, isNew bool) string {
	flags := []string{}
	if f.Exploit.KEV {
		flags = append(flags, "KEV")
	}
	if f.Exploit.Ransomware {
		flags = append(flags, "RANSOMWARE")
	}
	if isNew {
		flags = append(flags, "NEW")
	}
	if !f.HasFix() {
		flags = append(flags, "NO FIX")
	}
	if len(flags) == 0 {
		return ""
	}
	return "  [" + strings.Join(flags, " ") + "]"
}

func epssLabel(f finding.Finding) string {
	if !f.Exploit.EPSSKnown {
		return "epss —"
	}
	return fmt.Sprintf("epss %.2f%%", f.Exploit.EPSS*100)
}

func fixLabel(f finding.Finding) string {
	if !f.HasFix() {
		return "no fix available"
	}
	return "fix " + f.FixedIn
}

// writeSummary closes a scan. fixes is how many actions the grouped view
// reduced the findings to; zero means flat mode, which has nothing to add.
func writeSummary(w io.Writer, r Report, fixes int) {
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
		fmt.Fprintf(w, " — %d known exploited", kev)
	}
	fmt.Fprintln(w)
}
