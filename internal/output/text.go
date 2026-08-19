package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

func writeText(w io.Writer, r Report) error {
	writeWarnings(w, r.Warnings)
	if len(r.Findings) == 0 {
		_, err := fmt.Fprintf(w, "clear — %d packages, nothing held\n", r.Packages)
		return err
	}
	for _, f := range r.Findings {
		writeFinding(w, f, r.New[f.Key()])
	}
	writeSummary(w, r)
	return nil
}

func writeWarnings(w io.Writer, warnings []string) {
	for _, warn := range warnings {
		fmt.Fprintf(w, "  ! %s\n", warn)
	}
	if len(warnings) > 0 {
		fmt.Fprintln(w)
	}
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

func writeSummary(w io.Writer, r Report) {
	kev := 0
	for _, f := range r.Findings {
		if f.Exploit.KEV {
			kev++
		}
	}
	fmt.Fprintf(w, "%d held out of %d packages", len(r.Findings), r.Packages)
	if kev > 0 {
		fmt.Fprintf(w, " — %d known exploited", kev)
	}
	fmt.Fprintln(w)
}
