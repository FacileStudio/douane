package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/FacileStudio/douane/internal/enrich"
	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/inventory"
	"github.com/FacileStudio/douane/internal/osv"
	"github.com/FacileStudio/douane/internal/output"
)

const usage = `douane — customs for your dependencies

Usage:
  douane scan [path] [flags]

Flags:
  -format auto|text|line|json   output shape (default auto)
  -fail   never|low|medium|high|critical|kev   exit 1 at or above (default never)
  -db     path to the sweep database (default ~/.douane.db, "" to disable)
  -no-enrich                    skip the KEV and EPSS feeds

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
}

func parseArgs(args []string) (options, int) {
	opts := options{path: ".", dbPath: defaultDB()}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&opts.format, "format", "auto", "")
	fs.StringVar(&opts.failOn, "fail", "never", "")
	fs.StringVar(&opts.dbPath, "db", opts.dbPath, "")
	fs.BoolVar(&opts.noEnrich, "no-enrich", false, "")

	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		opts.path, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return opts, 2
	}
	return opts, 0
}

func runScan(args []string) int {
	opts, code := parseArgs(args)
	if code != 0 {
		return code
	}
	threshold, ok := parseFail(opts.failOn)
	if !ok {
		fmt.Fprintf(os.Stderr, "douane: unknown -fail value %q\n", opts.failOn)
		return 2
	}
	report, code := sweep(context.Background(), opts)
	if code != 0 {
		return code
	}
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

func sweep(ctx context.Context, opts options) (output.Report, int) {
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
		enrichReport(ctx, &report)
	}
	finding.Rank(report.Findings)

	if opts.dbPath != "" {
		if err := history(opts.dbPath, &report); err != nil {
			report.Warnings = append(report.Warnings,
				fmt.Sprintf("sweep history unavailable: %v", err))
		}
	}
	return report, 0
}

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

func enrichReport(ctx context.Context, report *output.Report) {
	res := enrich.New().Apply(ctx, report.Findings)
	if !res.KEVOK {
		report.Warnings = append(report.Warnings,
			fmt.Sprintf("KEV feed unavailable, ranking degraded: %v", res.KEVErr))
	}
	if !res.EPSSOK {
		report.Warnings = append(report.Warnings,
			fmt.Sprintf("EPSS feed unavailable, ranking degraded: %v", res.EPSSErr))
	}
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
