package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/FacileStudio/douane/internal/enrich"
	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/inventory"
	"github.com/FacileStudio/douane/internal/output"
	"github.com/FacileStudio/douane/internal/store"
)

const usage = `douane — customs for your dependencies

Usage:
  douane scan  [path] [flags]   inspect one project
  douane sweep [dir]  [flags]   inspect every repository under a directory

Flags:
  -format auto|text|line|json   output shape (default auto)
  -fail   never|low|medium|high|critical|kev   exit 1 at or above (default never)
  -db     path to the sweep database (default ~/.douane.db, "" to disable)
  -no-enrich                    skip the KEV and EPSS feeds
  -refresh                      refetch the feeds, ignoring the cache

Exit codes: 0 clear, 1 findings at or above -fail, 2 bad usage or unreadable input.
`

// Run executes douane and returns the process exit code.
func Run(args []string) int {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:])
	case "sweep":
		return runSweep(args[1:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "douane: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

type options struct {
	path     string
	format   string
	failOn   string
	dbPath   string
	noEnrich bool
	refresh  bool
}

func parseArgs(name string, args []string) (options, int) {
	opts := options{path: ".", dbPath: defaultDB()}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&opts.format, "format", "auto", "")
	fs.StringVar(&opts.failOn, "fail", "never", "")
	fs.StringVar(&opts.dbPath, "db", opts.dbPath, "")
	fs.BoolVar(&opts.noEnrich, "no-enrich", false, "")
	fs.BoolVar(&opts.refresh, "refresh", false, "")

	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		opts.path, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return opts, 2
	}
	return opts, 0
}

func runScan(args []string) int {
	opts, code := parseArgs("scan", args)
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
	report, code := scanOne(context.Background(), opts, st)
	if code != 0 {
		return code
	}
	report.Warnings = append(warnings, report.Warnings...)

	form := output.Resolve(output.Format(opts.format), os.Stdout)
	if err := output.Write(os.Stdout, form, report); err != nil {
		fmt.Fprintf(os.Stderr, "douane: %v\n", err)
		return 2
	}
	if shouldFail(report.Findings, threshold) {
		return 1
	}
	return 0
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
		return output.Report{}, 2
	}
	pkgs, err := inventory.Scan(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "douane: %v\n", err)
		return output.Report{}, 2
	}
	report := output.Report{Target: target, Packages: len(pkgs), New: map[string]bool{}}
	if len(pkgs) == 0 {
		report.Warnings = append(report.Warnings, "no lockfile found — nothing to inspect")
		return report, 0
	}
	if code := resolve(ctx, pkgs, &report); code != 0 {
		return output.Report{}, code
	}
	if !opts.noEnrich {
		res := newEnricher(opts, st).Apply(ctx, report.Findings)
		report.Warnings = append(report.Warnings, enrichWarnings(res)...)
	}
	finding.Rank(report.Findings)

	if st != nil {
		if err := history(st, &report); err != nil {
			report.Warnings = append(report.Warnings,
				fmt.Sprintf("sweep history unavailable: %v", err))
		}
	}
	return report, 0
}

func newEnricher(opts options, st *store.Store) *enrich.Enricher {
	e := enrich.New().WithRefresh(opts.refresh)
	if st != nil {
		e = e.WithCache(st)
	}
	return e
}

// enrichWarnings turns a feed result into what the reader needs to know: a
// feed that answered says nothing, a feed served from an expired cache says
// how old it is, and a feed that failed outright says why.
func enrichWarnings(res enrich.Result) []string {
	var out []string
	switch {
	case !res.KEVOK:
		out = append(out, fmt.Sprintf("KEV feed unavailable, ranking degraded: %v", res.KEVErr))
	case res.KEVStale:
		out = append(out, fmt.Sprintf("KEV feed unreachable — using a cached catalogue from %s ago",
			age(res.KEVAge)))
	}
	if res.CacheErr != nil {
		out = append(out, fmt.Sprintf("feed cache not written, the next run will refetch: %v", res.CacheErr))
	}
	switch {
	case !res.EPSSOK:
		out = append(out, fmt.Sprintf("EPSS feed unavailable, ranking degraded: %v", res.EPSSErr))
	case res.EPSSStale:
		out = append(out, "EPSS feed unreachable — ranking uses cached scores only")
	}
	return out
}

func age(d time.Duration) string {
	if d < time.Hour {
		return "under an hour"
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}
