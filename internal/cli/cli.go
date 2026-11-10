package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/FacileStudio/douane/internal/enrich"
	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/inventory"
	"github.com/FacileStudio/douane/internal/osv"
	"github.com/FacileStudio/douane/internal/output"
	"github.com/FacileStudio/douane/internal/permit"
	"github.com/FacileStudio/douane/internal/store"
	"github.com/FacileStudio/douane/internal/version"
)

const usage = `douane — customs for your dependencies

Usage:
  douane scan  [path] [flags]   inspect one project
  douane sweep [dir]  [flags]   inspect every repository under a directory

The path may be given before or after the flags.

Flags:
  -format auto|text|line|json|sarif
                                output shape (default auto)
  -by     fix|finding           group by the fix that clears findings (default fix),
                                or print every finding on its own
  -fail   never|any|low|medium|high|critical|kev
                                exit 1 at or above (default never)
  -scope  all|prod|dev          filter findings by how far they reach a runtime
                                (default all)
  -informational warn|fail|ignore
                                treat RUSTSEC informational defects (unmaintained,
                                unsound) as warnings, CI failures, or hide them
                                (default warn)
  -db     path to the sweep database (default ~/.douane.db, "" to disable)
  -no-enrich                    skip the KEV and EPSS feeds
  -refresh                      refetch the feeds, ignoring the cache
  -include-testdata             also read directories named testdata, which are
                                skipped like vendor and node_modules by default
  -timeout duration             stop the whole run after this long (default 10m)
  --version                     print the version and exit

Permits:
  douane.yml at a project's root suppresses a finding until a date. Every
  entry needs id, reason and expires (YYYY-MM-DD, at most 365 days ahead);
  package is optional. A lapsed permit returns its finding marked
  EXPIRED PERMIT and exits 1 whatever -fail says.

Exit codes:
  0  clear
  1  findings at or above -fail, or a finding whose permit has lapsed
  2  bad usage or unreadable input, an invalid douane.yml included
  3  scan incomplete — douane could not determine part of the answer
`

// Run executes douane and returns the process exit code.
func Run(args []string) int {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:])
	case "sweep":
		return runSweep(args[1:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return exitClear
	case "-version", "--version":
		fmt.Printf("douane %s\n", version.String())
		return exitClear
	default:
		fmt.Fprintf(os.Stderr, "douane: unknown command %q\n\n%s", args[0], usage)
		return exitUsage
	}
}

func runScan(args []string) int {
	opts, code := parseArgs("scan", args)
	if code != exitClear || opts.done {
		return code
	}
	today := permit.Today()
	permits, ok := loadPermits(opts.path, today)
	if !ok {
		return exitUsage
	}
	st, warnings := openStore(opts.dbPath)
	if st != nil {
		defer st.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	report, code := scanOne(ctx, opts, st)
	if code != exitClear {
		return code
	}
	report.Warnings = append(warnings, report.Warnings...)
	applyPermits(&report, permits, today)
	form := output.Resolve(output.Format(opts.format), os.Stdout)
	if err := output.WriteTo(os.Stdout, os.Stderr, form, output.Layout(opts.by), report); err != nil {
		fmt.Fprintf(os.Stderr, "douane: %v\n", err)
		return exitUsage
	}
	return permitExit(exitFor(report.Findings, report.Gaps, opts.fail), report)
}

// openStore opens the sweep database, which carries both the history and the
// feed cache. A database that will not open costs history and caching, never
// the sweep itself.
func openStore(path string) (*store.Store, []string) {
	if path == "" {
		return nil, nil
	}
	st, err := store.Open(path)
	if err != nil {
		return nil, []string{fmt.Sprintf("sweep database unavailable: %v", err)}
	}
	return st, nil
}

func scanOne(ctx context.Context, opts options, st *store.Store) (output.Report, int) {
	target, err := filepath.Abs(opts.path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "douane: %v\n", err)
		return output.Report{}, exitUsage
	}
	pkgs, gaps, err := inventory.Scan(target, opts.walk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "douane: %v\n", err)
		return output.Report{}, exitUsage
	}
	build, buildGaps := inventory.BuildLines(target, opts.walk)
	report := output.Report{Target: target, Packages: len(pkgs), New: map[string]bool{},
		Gaps: append(gaps, buildGaps...), BuildLines: build}
	if len(pkgs) == 0 {
		report.Gaps = append(report.Gaps, finding.Gap{Kind: finding.GapUnsupported,
			Subject: target, Detail: "no lockfile found, nothing was inspected"})
		return report, exitClear
	}
	resolve(ctx, osv.New(), pkgs, &report)
	if !opts.noEnrich {
		res := newEnricher(opts, st).Apply(ctx, report.Findings)
		report.Warnings = append(report.Warnings, enrichWarnings(res)...)
		report.Gaps = append(report.Gaps, res.Gaps...)
	}
	narrow(&report, opts.scopeFilter(), opts.informational == "ignore")
	record(st, &report)
	return report, exitClear
}

func newEnricher(opts options, st *store.Store) *enrich.Enricher {
	e := enrich.New().WithRefresh(opts.refresh)
	if st != nil {
		e = e.WithCache(st)
	}
	return e
}

// enrichWarnings reports what a feed cost the reader without costing the
// answer. Everything a feed could not determine travels as a gap instead,
// because only a gap reaches the exit code — a cache that refused the write is
// the one case here that leaves the answer whole.
func enrichWarnings(res enrich.Result) []string {
	if res.CacheErr == nil {
		return nil
	}
	return []string{fmt.Sprintf("feed cache not written, the next run will refetch: %v", res.CacheErr)}
}
