package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/osv"
	"github.com/FacileStudio/douane/internal/output"
)

func resolve(ctx context.Context, pkgs []finding.Package, report *output.Report) int {
	client := osv.New()
	ids, err := client.Query(ctx, pkgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "douane: %v\n", err)
		return 2
	}
	var flat []string
	for _, list := range ids {
		flat = append(flat, list...)
	}
	vulns, err := client.Fetch(ctx, flat)
	if err != nil {
		report.Warnings = append(report.Warnings,
			fmt.Sprintf("some advisories could not be fetched: %v", err))
	}
	report.Findings = build(pkgs, ids, vulns)
	return 0
}

func build(pkgs []finding.Package, ids [][]string, vulns map[string]osv.Vuln) []finding.Finding {
	var out []finding.Finding
	seen := map[string]bool{}
	for i, pkg := range pkgs {
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
		}
	}
	return out
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
