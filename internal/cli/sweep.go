package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/osv"
	"github.com/FacileStudio/douane/internal/output"
	"github.com/FacileStudio/douane/internal/permit"
	"github.com/FacileStudio/douane/internal/store"
)

// repoScan is one repository mid-sweep: its packages, its own permits, and
// the report being assembled for it.
type repoScan struct {
	report  output.Report
	pkgs    []finding.Package
	permits []permit.Permit
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
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	result, code := sweepAll(ctx, opts, st)
	if code != exitClear {
		return code
	}
	result.Warnings = append(warnings, result.Warnings...)

	form := output.Resolve(output.Format(opts.format), os.Stdout)
	if err := output.WriteSweepTo(os.Stdout, os.Stderr, form, output.Layout(opts.by), result); err != nil {
		fmt.Fprintf(os.Stderr, "douane: %v\n", err)
		return exitUsage
	}
	return permitExit(sweepExit(result, opts.fail), result.Repos...)
}

// sweepExit applies exitFor to the whole fleet. Findings at or above -fail exit
// 1 and outrank everything else, because "you are vulnerable" is a finished
// answer. Short of that, any gap in the fleet, an unreadable repository
// included, exits 3, unless -fail is never, which always exits 0.
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
	attachPermits(repos, permit.Today())
	sweep := output.Sweep{Root: root}
	if len(repos) == 0 {
		sweep.Warnings = append(sweep.Warnings, "no project found under "+root)
		return sweep, exitClear
	}
	resolveFleet(ctx, osv.New(), repos, &sweep)
	if !opts.noEnrich {
		warnings, gaps := enrichFleet(ctx, opts, st, repos)
		sweep.Warnings = append(sweep.Warnings, warnings...)
		sweep.Gaps = append(sweep.Gaps, gaps...)
	}
	collect(repos, st, &sweep, opts.scopeFilter, opts.informational)
	return sweep, exitClear
}

// resolveFleet asks OSV about the fleet's unique packages once. A chunk that
// failed costs its own packages and nothing else, so the fleet keeps every
// answer that did arrive and reports the rest as gaps: on the fleet, and on
// every repository whose answer the failure can have emptied, so a consumer
// reading one repository never sees an outage as a clean result. The joined
// errors are dropped because they say nothing the gaps beside them do not.
func resolveFleet(ctx context.Context, client *osv.Client, repos []*repoScan, sweep *output.Sweep) {
	unique := union(repos)
	if len(unique) == 0 {
		return
	}
	idx, queryGaps, _ := client.Query(ctx, unique)
	ids := indexIDs(unique, idx)
	vulns, fetchGaps, _ := client.Fetch(ctx, flatIDs(ids))
	sweep.Gaps = append(append(sweep.Gaps, queryGaps...), fetchGaps...)
	absent := client.Absent()
	for _, r := range repos {
		findings, rangeGaps := buildFrom(r.pkgs, ids, vulns, absent)
		r.report.Findings = findings
		r.report.Gaps = append(r.report.Gaps, rangeGaps...)
		r.report.Gaps = append(r.report.Gaps, repoGaps(r.pkgs, ids, queryGaps, fetchGaps)...)
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
func buildFrom(pkgs []finding.Package, ids map[string][]string,
	vulns map[string]osv.Vuln, absent map[string]bool) ([]finding.Finding, []finding.Gap) {
	byIndex := make([][]string, len(pkgs))
	for i, p := range pkgs {
		byIndex[i] = ids[pkgKey(p)]
	}
	return build(pkgs, byIndex, vulns, absent)
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

// collect ranks each repository, filters it to the requested scope, records
// its history, applies its permits, lets those permits cover the fleet gaps
// only their findings raised, and orders the fleet so the first group printed
// is the one to open first.
func collect(repos []*repoScan, st *store.Store, sweep *output.Sweep, scope finding.ScopeFilter, info string) {
	for _, r := range repos {
		finding.Rank(r.report.Findings)
		r.report.Findings = finding.FilterScope(r.report.Findings, scope)
		r.report.Findings = finding.FilterInformational(r.report.Findings, info == "ignore")
		record(st, &r.report)
		applyPermits(&r.report, r.permits, permit.Today())
		sweep.Repos = append(sweep.Repos, r.report)
	}
	coverFleetGaps(sweep)
	output.SortRepos(sweep.Repos)
}
