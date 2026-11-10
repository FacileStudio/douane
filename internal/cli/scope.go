package cli

import (
	"fmt"
	"os"
	"slices"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/output"
)

// resolveScope validates -scope. prod, dev and all are the only values sweep
// understands; anything else is a usage error and stops the invocation.
func resolveScope(opts *options) int {
	if _, ok := parseScope(opts.scope); ok {
		return exitClear
	}
	fmt.Fprintf(os.Stderr, "douane: unknown -scope value %q\n", opts.scope)
	return exitUsage
}

// scopeFilter is which findings survive -scope, read from the value
// resolveScope already validated.
func (o options) scopeFilter() finding.ScopeFilter {
	f, _ := parseScope(o.scope)
	return f
}

// narrow ranks a report, filters it to the requested scope and informational
// mode, and sets aside the gaps that concerned only the findings the scope
// removed: the reader chose not to look at those findings, so a gap about one
// is not an incomplete answer to the question asked. A gap that also concerns
// a finding still in scope stays, and a gap about the scan concerns no
// finding, so the scope never removes it.
func narrow(report *output.Report, scope finding.ScopeFilter, ignoreInfo bool) {
	finding.Rank(report.Findings)
	all := report.Findings
	report.Findings = finding.FilterScope(all, scope)
	report.Gaps, report.OutOfScope = splitScope(report.Gaps, all, report.Findings)
	report.Findings = finding.FilterInformational(report.Findings, ignoreInfo)
}

// splitScope separates the gaps that concern a finding of all, and none of
// kept, from the rest.
func splitScope(gaps []finding.Gap, all, kept []finding.Finding) ([]finding.Gap, []finding.Gap) {
	var in, out []finding.Gap
	for _, g := range gaps {
		if slices.ContainsFunc(all, g.Concerns) && !slices.ContainsFunc(kept, g.Concerns) {
			out = append(out, g)
			continue
		}
		in = append(in, g)
	}
	return in, out
}

func parseScope(s string) (finding.ScopeFilter, bool) {
	switch s {
	case "prod":
		return finding.FilterProd, true
	case "dev":
		return finding.FilterDev, true
	case "all":
		return finding.FilterAll, true
	}
	return finding.FilterAll, false
}
