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
func writeGroup(w io.Writer, g finding.Group) {
	worst := g.WorstFinding()
	action := g.Package
	if len(g.Installed) > 0 {
		action += " " + capAt(g.Installed, 3)
	}
	if g.FixedIn == "" {
		action += " → no fix"
	} else {
		action += " → " + g.FixedIn
	}
	fmt.Fprintf(w, "%-9s %d finding%s · %s · %s%s\n",
		g.Worst, g.Count, plural(g.Count), g.Ecosystem, action,
		badge(worst, g.New > 0))
	writeGroupDetail(w, g, worst)
	if worst.Summary != "" {
		fmt.Fprintf(w, "          worst: %s\n", worst.Summary)
	}
	fmt.Fprintln(w)
}

// writeGroupDetail carries the advisory ids, exploit likelihood and affected
// targets under the headline, capped so a fleet-wide package stays one block.
func writeGroupDetail(w io.Writer, g finding.Group, worst finding.Finding) {
	detail := capAt(g.IDs, 3)
	if !worst.Exploit.EPSSKnown {
		detail += " · epss —"
	} else {
		detail += fmt.Sprintf(" · epss %.2f%%", worst.Exploit.EPSS*100)
	}
	detail += fmt.Sprintf(" · %d target%s: %s", len(g.Targets), plural(len(g.Targets)),
		capAt(g.Targets, 5))
	fmt.Fprintf(w, "          %s\n", detail)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
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
