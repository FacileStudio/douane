package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/osv"
	"github.com/FacileStudio/douane/internal/output"
	"github.com/FacileStudio/douane/internal/store"
)

// repoScan is one repository mid-sweep: its packages, and the report being
// assembled for it.
type repoScan struct {
	report output.Report
	pkgs   []finding.Package
}

func runSweep(args []string) int {
	opts, code := parseArgs("sweep", args)
	if code != exitClear || opts.done {
		return code
	}
	st, warnings := openStore(opts.dbPath)
	if st != nil {
		defer st.Close()
	}
	result, code := sweepAll(context.Background(), opts, st)
	if code != exitClear {
		return code
	}
	result.Warnings = append(warnings, result.Warnings...)

	form := output.Resolve(output.Format(opts.format), os.Stdout)
	if err := output.WriteSweepTo(os.Stdout, os.Stderr, form, result); err != nil {
		fmt.Fprintf(os.Stderr, "douane: %v\n", err)
		return exitUsage
	}
	return sweepExit(result, opts.fail)
}

// sweepExit ranks the two ways a fleet run can be bad. A repository that could
// not be read outranks a finding: an unscannable repository leaves the fleet
// silently, which is a false negative, and `scan` already exits 2 for it.
func sweepExit(s output.Sweep, t threshold) int {
	var all []finding.Finding
	for _, r := range s.Repos {
		all = append(all, r.Findings...)
	}
	return exitFor(all, s.AllGaps(), t)
}

// sweepAll scans every repository under root against one shared resolution.
// Repositories overlap heavily — two forks of the same app share a thousand
// packages — so the fleet is resolved as a single set of unique packages and
// the results are handed back out, rather than asking OSV the same questions
// once per repository.
func sweepAll(ctx context.Context, opts options, st *store.Store) (output.Sweep, int) {
	root, err := filepath.Abs(opts.path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "douane: %v\n", err)
		return output.Sweep{}, exitUsage
	}
	dirs, err := discover(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "douane: %v\n", err)
		return output.Sweep{}, exitUsage
	}
	repos := inventories(dirs)
	sweep := output.Sweep{Root: root}
	if len(repos) == 0 {
		sweep.Warnings = append(sweep.Warnings, "no project found under "+root)
		return sweep, exitClear
	}
	resolveFleet(ctx, repos, &sweep)
	if !opts.noEnrich {
		warnings, gaps := enrichFleet(ctx, opts, st, repos)
		sweep.Warnings = append(sweep.Warnings, warnings...)
		sweep.Gaps = append(sweep.Gaps, gaps...)
	}
	collect(repos, st, &sweep)
	return sweep, exitClear
}

// resolveFleet asks OSV about the fleet's unique packages once. A chunk that
// failed costs its own packages and nothing else, so the fleet keeps every
// answer that did arrive and reports the rest as gaps. The joined errors are
// dropped because they say nothing the gaps beside them do not.
func resolveFleet(ctx context.Context, repos []*repoScan, sweep *output.Sweep) {
	unique := union(repos)
	if len(unique) == 0 {
		return
	}
	client := osv.New()
	idx, gaps, _ := client.Query(ctx, unique)
	sweep.Gaps = append(sweep.Gaps, gaps...)
	ids := map[string][]string{}
	var flat []string
	for i, list := range idx {
		if len(list) == 0 {
			continue
		}
		ids[pkgKey(unique[i])] = list
		flat = append(flat, list...)
	}
	vulns, fetchGaps, _ := client.Fetch(ctx, flat)
	sweep.Gaps = append(sweep.Gaps, fetchGaps...)
	for _, r := range repos {
		findings, rangeGaps := buildFrom(r.pkgs, ids, vulns)
		r.report.Findings = findings
		r.report.Gaps = append(r.report.Gaps, rangeGaps...)
	}
}

func union(repos []*repoScan) []finding.Package {
	seen := map[string]bool{}
	var out []finding.Package
	for _, r := range repos {
		for _, p := range r.pkgs {
			key := pkgKey(p)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, p)
		}
	}
	return out
}

// buildFrom builds one repository's findings from the shared resolution. It
// walks that repository's own packages, so a finding reports the lockfile it
// was actually read from, and dedup stays per repository.
func buildFrom(pkgs []finding.Package, ids map[string][]string, vulns map[string]osv.Vuln) ([]finding.Finding, []finding.Gap) {
	byIndex := make([][]string, len(pkgs))
	for i, p := range pkgs {
		byIndex[i] = ids[pkgKey(p)]
	}
	return build(pkgs, byIndex, vulns)
}

// enrichFleet enriches every finding in one pass, then hands the annotated
// copies back to the repository they came from. It returns the feeds' gaps
// alongside their warnings: a feed that never answered leaves the fleet's KEV
// and EPSS columns empty, and that is a hole in the answer, not a clean run.
func enrichFleet(ctx context.Context, opts options, st *store.Store, repos []*repoScan) ([]string, []finding.Gap) {
	var all []finding.Finding
	for _, r := range repos {
		all = append(all, r.report.Findings...)
	}
	if len(all) == 0 {
		return nil, nil
	}
	res := newEnricher(opts, st).Apply(ctx, all)
	at := 0
	for _, r := range repos {
		n := len(r.report.Findings)
		copy(r.report.Findings, all[at:at+n])
		at += n
	}
	return enrichWarnings(res), res.Gaps
}

// collect ranks each repository, records its history and orders the fleet so
// the first group printed is the one to open first.
func collect(repos []*repoScan, st *store.Store, sweep *output.Sweep) {
	for _, r := range repos {
		finding.Rank(r.report.Findings)
		record(st, &r.report)
		sweep.Repos = append(sweep.Repos, r.report)
	}
	output.SortRepos(sweep.Repos)
}
