package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

func writeText(w io.Writer, r Report, l Layout) error {
	th := newTheme(w)
	writeNotesText(w, th, r.Gaps, r.Warnings)
	if len(r.Findings) == 0 {
		return writeNothingHeld(w, th, r)
	}
	if l == LayoutFinding {
		for _, f := range r.Findings {
			writeFinding(w, th, f, r.New[f.Key()])
		}
		writeSummary(w, th, r, 0)
		return nil
	}
	groups := finding.Groups(r.Findings, isNewFn(r))
	for _, g := range groups {
		writeGroup(w, th, g)
	}
	writeSummary(w, th, r, len(groups))
	return nil
}

// writeNothingHeld closes a scan that held nothing. It says clear only when
// douane determined the whole answer: an incomplete scan that found nothing
// has not established that there is nothing to find.
func writeNothingHeld(w io.Writer, th theme, r Report) error {
	if !r.Complete() {
		_, err := fmt.Fprintf(w, "%s %s %d packages, nothing held, %d unanswered\n",
			th.warn("incomplete"), th.dim(th.None), r.Packages, len(r.Gaps))
		return err
	}
	_, err := fmt.Fprintf(w, "%s %s %d packages, nothing held\n",
		th.fix("clear"), th.dim(th.None), r.Packages)
	return err
}

func writeFinding(w io.Writer, th theme, f finding.Finding, isNew bool) {
	sep := " " + th.dim(th.Sep) + " "
	fmt.Fprintf(w, "%s %s  %s%s %s%s\n",
		th.mark(f.Severity, th.Mark), th.mark(f.Severity, pad(f.Severity.String(), 8)),
		th.dim(f.Ecosystem+":"), th.bold(f.Package), th.dim(f.Installed),
		badge(th, f, isNew))
	fmt.Fprintf(w, "      %s%s%s%s%s\n",
		th.dim(f.ID), sep, epssLabel(th, f), sep, fixLabel(th, f))
	fmt.Fprintf(w, "      %s\n", th.dim(f.Target))
	if f.Summary != "" {
		fmt.Fprintf(w, "    %s %s\n", th.dim(th.Arrow), th.dim(f.Summary))
	}
	fmt.Fprintln(w)
}

func badge(th theme, f finding.Finding, isNew bool) string {
	flags := []string{}
	if f.Exploit.KEV {
		flags = append(flags, th.alarm("KEV"))
	}
	if f.Exploit.Ransomware {
		flags = append(flags, th.alarm("RANSOMWARE"))
	}
	if isNew {
		flags = append(flags, th.warn("NEW"))
	}
	if !f.HasFix() {
		flags = append(flags, th.warn("NO FIX"))
	}
	if len(flags) == 0 {
		return ""
	}
	return "  [" + strings.Join(flags, " ") + "]"
}

func epssLabel(th theme, f finding.Finding) string {
	if !f.Exploit.EPSSKnown {
		return th.dim("epss " + th.None)
	}
	label := fmt.Sprintf("epss %.2f%%", f.Exploit.EPSS*100)
	if f.Exploit.EPSS >= epssNotable {
		return th.warn(label)
	}
	return th.dim(label)
}

func fixLabel(th theme, f finding.Finding) string {
	if !f.HasFix() {
		return th.warn("no fix available")
	}
	return th.dim("fix ") + th.fix(f.FixedIn)
}

// writeSummary closes a scan with two lines, after filet: what was measured,
// then what was found. The severity spread is the second line's whole point —
// "3816 held" is a number, and "136 critical · 1632 high" is the shape of the
// problem, which is what decides whether you open the report tonight.
func writeSummary(w io.Writer, th theme, r Report, n int) {
	sep := " " + th.dim(th.Sep) + " "
	scope := fmt.Sprintf("%d held", len(r.Findings)) + sep +
		th.dim(fmt.Sprintf("%d packages", r.Packages))
	if n > 0 {
		scope += sep + th.dim(fmt.Sprintf("%d %s", n, fixes(n)))
	}
	fmt.Fprintf(w, "  %s\n  %s\n", scope, spread(th, r.Findings))
}

// spread renders the severity distribution, dropping the tiers that are empty
// so a clean-ish scan does not print four zeroes.
func spread(th theme, fs []finding.Finding) string {
	counts := map[finding.Severity]int{}
	kev := 0
	for _, f := range fs {
		counts[f.Severity]++
		if f.Exploit.KEV {
			kev++
		}
	}
	var parts []string
	for _, s := range []finding.Severity{finding.SevCritical, finding.SevHigh,
		finding.SevMedium, finding.SevLow, finding.SevUnknown} {
		if n := counts[s]; n > 0 {
			parts = append(parts, th.mark(s, fmt.Sprintf("%d %s", n, strings.ToLower(s.String()))))
		}
	}
	if kev > 0 {
		parts = append(parts, th.alarm(fmt.Sprintf("%d known exploited", kev)))
	}
	return strings.Join(parts, " "+th.dim(th.Sep)+" ")
}
