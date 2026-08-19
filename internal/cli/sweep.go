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
	if code != 0 {
		return code
	}
	threshold, ok := parseFail(opts.failOn)
	if !ok {
		fmt.Fprintf(os.Stderr, "douane: unknown -fail value %q\n", opts.failOn)
		return 2
	}
	st, warnings := openStore(opts.dbPath)
	if st != nil {
		defer st.Close()
	}
	result, code := sweepAll(context.Background(), opts, st)
	if code != 0 {
		return code
	}
	result.Warnings = append(warnings, result.Warnings...)

	form := output.Resolve(output.Format(opts.format), os.Stdout)
	if err := output.WriteSweep(os.Stdout, form, result); err != nil {
		fmt.Fprintf(os.Stderr, "douane: %v\n", err)
		return 2
	}
	return sweepExit(result, threshold)
}

// sweepExit ranks the two ways a fleet run can be bad. A repository that could
// not be read outranks a finding: an unscannable repository leaves the fleet
// silently, which is a false negative, and `scan` already exits 2 for it.
func sweepExit(s output.Sweep, threshold int) int {
	for _, r := range s.Repos {
		if r.Failed {
			return 2
		}
	}
	for _, r := range s.Repos {
		if shouldFail(r.Findings, threshold) {
			return 1
		}
	}
	return 0
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
		return output.Sweep{}, 2
	}
	dirs, err := discover(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "douane: %v\n", err)
		return output.Sweep{}, 2
	}
	repos := inventories(dirs)
	sweep := output.Sweep{Root: root}
	if len(repos) == 0 {
		sweep.Warnings = append(sweep.Warnings, "no project found under "+root)
		return sweep, 0
	}
	if code := resolveFleet(ctx, repos, &sweep); code != 0 {
		return output.Sweep{}, code
	}
	if !opts.noEnrich {
		sweep.Warnings = append(sweep.Warnings, enrichFleet(ctx, opts, st, repos)...)
	}
	collect(repos, st, &sweep)
	return sweep, 0
}

func resolveFleet(ctx context.Context, repos []*repoScan, sweep *output.Sweep) int {
	unique := union(repos)
	if len(unique) == 0 {
		return 0
	}
	client := osv.New()
	idx, err := client.Query(ctx, unique)
	if err != nil {
		fmt.Fprintf(os.Stderr, "douane: %v\n", err)
		return 2
	}
	ids := map[string][]string{}
	var flat []string
	for i, list := range idx {
		if len(list) == 0 {
			continue
		}
		ids[pkgKey(unique[i])] = list
		flat = append(flat, list...)
	}
	vulns, err := client.Fetch(ctx, flat)
	if err != nil {
		sweep.Warnings = append(sweep.Warnings,
			fmt.Sprintf("some advisories could not be fetched: %v", err))
	}
	for _, r := range repos {
		r.report.Findings = buildFrom(r.pkgs, ids, vulns)
	}
	return 0
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
func buildFrom(pkgs []finding.Package, ids map[string][]string, vulns map[string]osv.Vuln) []finding.Finding {
	byIndex := make([][]string, len(pkgs))
	for i, p := range pkgs {
		byIndex[i] = ids[pkgKey(p)]
	}
	return build(pkgs, byIndex, vulns)
}

// enrichFleet enriches every finding in one pass, then hands the annotated
// copies back to the repository they came from.
func enrichFleet(ctx context.Context, opts options, st *store.Store, repos []*repoScan) []string {
	var all []finding.Finding
	for _, r := range repos {
		all = append(all, r.report.Findings...)
	}
	if len(all) == 0 {
		return nil
	}
	res := newEnricher(opts, st).Apply(ctx, all)
	at := 0
	for _, r := range repos {
		n := len(r.report.Findings)
		copy(r.report.Findings, all[at:at+n])
		at += n
	}
	return enrichWarnings(res)
}

// collect ranks each repository, records its history and orders the fleet so
// the first group printed is the one to open first.
func collect(repos []*repoScan, st *store.Store, sweep *output.Sweep) {
	for _, r := range repos {
		finding.Rank(r.report.Findings)
		if st != nil {
			if err := history(st, &r.report); err != nil {
				r.report.Warnings = append(r.report.Warnings,
					fmt.Sprintf("sweep history unavailable: %v", err))
			}
		}
		sweep.Repos = append(sweep.Repos, r.report)
	}
	output.SortRepos(sweep.Repos)
}
