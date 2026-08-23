package cli

import (
	"context"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/osv"
	"github.com/FacileStudio/douane/internal/output"
)

// resolve asks OSV about every package and keeps whatever came back. A chunk
// that failed is a gap, not an abort: OSV answering for 500 packages and
// refusing the next 500 is a partial answer, and throwing it away to exit 2
// would report bad input for what is really an upstream outage. Both errors
// are dropped rather than warned about, because each is the join of the very
// failures the gaps beside them already name, one gap per failure.
func resolve(ctx context.Context, pkgs []finding.Package, report *output.Report) {
	client := osv.New()
	ids, gaps, _ := client.Query(ctx, pkgs)
	report.Gaps = append(report.Gaps, gaps...)
	var flat []string
	for _, list := range ids {
		flat = append(flat, list...)
	}
	vulns, fetchGaps, _ := client.Fetch(ctx, flat)
	report.Gaps = append(report.Gaps, fetchGaps...)
	findings, rangeGaps := build(pkgs, ids, vulns)
	report.Findings = findings
	report.Gaps = append(report.Gaps, rangeGaps...)
}

// build pairs each package with the advisories resolved for it. It walks only
// as far as the resolution reaches: a failed query answers for fewer packages
// than it was asked about, and reading past what came back is how a partial
// answer turns into a panic.
func build(pkgs []finding.Package, ids [][]string, vulns map[string]osv.Vuln) ([]finding.Finding, []finding.Gap) {
	var out []finding.Finding
	var gaps []finding.Gap
	seen := map[string]bool{}
	for i, pkg := range pkgs[:min(len(pkgs), len(ids))] {
		for _, id := range ids[i] {
			v, ok := vulns[id]
			if !ok {
				continue
			}
			f := newFinding(v, pkg)
			if seen[f.Key()] {
				continue
			}
			seen[f.Key()] = true
			out = append(out, f)
			gaps = append(gaps, osv.RangeGaps(v, pkg)...)
		}
	}
	return out, gaps
}

func newFinding(v osv.Vuln, pkg finding.Package) finding.Finding {
	canonical, aliases := osv.Canonical(v)
	sev, vector := osv.Severity(v)
	return finding.Finding{
		ID:        canonical,
		Aliases:   aliases,
		Summary:   v.Summary,
		Severity:  sev,
		CVSS:      vector,
		Package:   pkg.Name,
		Ecosystem: pkg.Ecosystem,
		Installed: pkg.Version,
		FixedIn:   osv.FixedIn(v, pkg),
		Target:    pkg.Source,
		Sources:   []string{"osv"},
	}
}

func pkgKey(p finding.Package) string {
	return p.Ecosystem + "|" + p.Name + "|" + p.Version
}
