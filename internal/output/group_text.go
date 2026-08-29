package output

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

// capAt shortens a list the way a human reads it: the first few, then a count
// of the rest. The full list stays reachable in -by finding and in json.
func capAt(ss []string, n int) string {
	if len(ss) <= n {
		return strings.Join(ss, ", ")
	}
	return strings.Join(ss[:n], ", ") + " +" + strconv.Itoa(len(ss)-n)
}

// writeGroup renders one action: every finding cleared by taking one package
// to one target version. The worst member speaks for the group's rank; its
// summary is the only prose a decision needs.
func writeGroup(w io.Writer, st style, gl glyphs, g finding.Group) {
	worst := g.WorstFinding()
	arrow := " " + st.dim(gl.To) + " " + st.fix(g.FixedIn)
	if g.FixedIn == "" {
		arrow = " " + st.dim(gl.To) + " " + st.warn("no fix")
	}
	fmt.Fprintf(w, "%s %s  %s%s %s%s%s\n",
		st.mark(g.Worst, gl.Mark), st.mark(g.Worst, pad(g.Worst.String(), 8)),
		st.dim(g.Ecosystem+":"), st.bold(g.Package),
		st.dim(capAt(g.Installed, 3)), arrow, badge(st, worst, g.New > 0))
	if worst.Summary != "" {
		fmt.Fprintf(w, "    %s %s\n", st.dim(gl.Arrow), st.dim(worst.Summary))
	}
	writeGroupDetail(w, st, gl, g, worst)
	fmt.Fprintln(w)
}

// writeGroupDetail carries the advisory ids, exploit likelihood and affected
// targets under the headline, capped so a fleet-wide package stays one block.
func writeGroupDetail(w io.Writer, st style, gl glyphs, g finding.Group, worst finding.Finding) {
	sep := " " + st.dim(gl.Sep) + " "
	count := fmt.Sprintf("%d finding%s", g.Count, plural(g.Count))
	targets := fmt.Sprintf("%d target%s: %s", len(g.Targets), plural(len(g.Targets)),
		capAt(g.Targets, 5))
	fmt.Fprintf(w, "      %s%s%s%s%s\n",
		st.dim(count), sep, epssLabel(st, gl, worst), sep, st.dim(targets))
	fmt.Fprintf(w, "      %s\n", st.dim(capAt(g.IDs, 3)))
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// fixes is plural() for the one word in this report that does not take a bare
// s. Printing "29 fixs" in the closing line of a security tool undoes a lot of
// careful ranking.
func fixes(n int) string {
	if n == 1 {
		return "fix"
	}
	return "fixes"
}

// repoCount is how many repositories actually hold findings, for the grouped
// headline; a repo with only gaps is not part of the finding count.
func repoCount(s Sweep) int {
	n := 0
	for _, r := range s.Repos {
		if len(r.Findings) > 0 {
			n++
		}
	}
	return n
}
