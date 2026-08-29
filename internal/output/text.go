package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

func writeText(w io.Writer, r Report, l Layout) error {
	st, gl := newStyle(w), glyphsFor(w)
	writeNotesText(w, st, r.Gaps, r.Warnings)
	if len(r.Findings) == 0 {
		return writeNothingHeld(w, st, gl, r)
	}
	if l == LayoutFinding {
		for _, f := range r.Findings {
			writeFinding(w, st, gl, f, r.New[f.Key()])
		}
		writeSummary(w, st, gl, r, 0)
		return nil
	}
	groups := finding.Groups(r.Findings, isNewFn(r))
	for _, g := range groups {
		writeGroup(w, st, gl, g)
	}
	writeSummary(w, st, gl, r, len(groups))
	return nil
}

// writeNothingHeld closes a scan that held nothing. It says clear only when
// douane determined the whole answer: an incomplete scan that found nothing
// has not established that there is nothing to find.
func writeNothingHeld(w io.Writer, st style, gl glyphs, r Report) error {
	if !r.Complete() {
		_, err := fmt.Fprintf(w, "%s %s %d packages, nothing held, %d unanswered\n",
			st.warn("incomplete"), st.dim(gl.None), r.Packages, len(r.Gaps))
		return err
	}
	_, err := fmt.Fprintf(w, "%s %s %d packages, nothing held\n",
		st.fix("clear"), st.dim(gl.None), r.Packages)
	return err
}

func writeFinding(w io.Writer, st style, gl glyphs, f finding.Finding, isNew bool) {
	sep := " " + st.dim(gl.Sep) + " "
	fmt.Fprintf(w, "%s %s  %s%s %s%s\n",
		st.mark(f.Severity, gl.Mark), st.mark(f.Severity, pad(f.Severity.String(), 8)),
		st.dim(f.Ecosystem+":"), st.bold(f.Package), st.dim(f.Installed),
		badge(st, f, isNew))
	fmt.Fprintf(w, "      %s%s%s%s%s\n",
		st.dim(f.ID), sep, epssLabel(st, gl, f), sep, fixLabel(st, f))
	fmt.Fprintf(w, "      %s\n", st.dim(f.Target))
	if f.Summary != "" {
		fmt.Fprintf(w, "    %s %s\n", st.dim(gl.Arrow), st.dim(f.Summary))
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

func epssLabel(st style, gl glyphs, f finding.Finding) string {
	if !f.Exploit.EPSSKnown {
		return st.dim("epss " + gl.None)
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

// writeSummary closes a scan with two lines, after filet: what was measured,
// then what was found. The severity spread is the second line's whole point —
// "3816 held" is a number, and "136 critical · 1632 high" is the shape of the
// problem, which is what decides whether you open the report tonight.
func writeSummary(w io.Writer, st style, gl glyphs, r Report, n int) {
	sep := " " + st.dim(gl.Sep) + " "
	scope := fmt.Sprintf("%d held", len(r.Findings)) + sep +
		st.dim(fmt.Sprintf("%d packages", r.Packages))
	if n > 0 {
		scope += sep + st.dim(fmt.Sprintf("%d %s", n, fixes(n)))
	}
	fmt.Fprintf(w, "  %s\n  %s\n", scope, spread(st, gl, r.Findings))
}

// spread renders the severity distribution, dropping the tiers that are empty
// so a clean-ish scan does not print four zeroes.
func spread(st style, gl glyphs, fs []finding.Finding) string {
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
			parts = append(parts, st.mark(s, fmt.Sprintf("%d %s", n, strings.ToLower(s.String()))))
		}
	}
	if kev > 0 {
		parts = append(parts, st.alarm(fmt.Sprintf("%d known exploited", kev)))
	}
	return strings.Join(parts, " "+st.dim(gl.Sep)+" ")
}
