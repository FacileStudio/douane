package cli

import (
	"os"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
)

func TestParseArgsTakesThePathFromEitherSide(t *testing.T) {
	cliQuiet(t)
	cases := map[string][]string{
		"before": {"/target", "-no-enrich", "-fail", "critical"},
		"after":  {"-no-enrich", "-fail", "critical", "/target"},
		"around": {"-no-enrich", "/target", "-fail", "critical"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			opts, code := parseArgs("scan", args)
			if code != exitClear {
				t.Fatalf("code = %d, want %d", code, exitClear)
			}
			if opts.path != "/target" {
				t.Fatalf("path = %q, want /target — the path was dropped and douane would scan $PWD", opts.path)
			}
			if !opts.noEnrich || opts.failOn != "critical" {
				t.Fatalf("flags past the path were not read: noEnrich=%t fail=%q", opts.noEnrich, opts.failOn)
			}
		})
	}
}

func TestParseArgsRejectsASecondPath(t *testing.T) {
	cliQuiet(t)
	if _, code := parseArgs("scan", []string{"-no-enrich", "/a", "/b"}); code != exitUsage {
		t.Fatalf("code = %d, want %d — a leftover argument must not be ignored", code, exitUsage)
	}
}

func TestParseArgsRefusesKevWithoutTheFeed(t *testing.T) {
	cliQuiet(t)
	if _, code := parseArgs("scan", []string{"-fail", "kev", "-no-enrich"}); code != exitUsage {
		t.Fatalf("code = %d, want %d — -fail kev cannot be judged with the KEV feed off", code, exitUsage)
	}
	opts, code := parseArgs("scan", []string{"-fail", "kev"})
	if code != exitClear || !opts.fail.kev {
		t.Fatalf("code = %d kev = %t, want %d true", code, opts.fail.kev, exitClear)
	}
}

func TestParseArgsRejectsAnUnknownFail(t *testing.T) {
	cliQuiet(t)
	if _, code := parseArgs("scan", []string{"-fail", "sometimes"}); code != exitUsage {
		t.Fatalf("code = %d, want %d", code, exitUsage)
	}
}

func TestExitForRanksFindingsOverAnIncompleteScan(t *testing.T) {
	gaps := []finding.Gap{{Kind: finding.GapUpstream, Subject: "kev", Detail: "429"}}
	high := []finding.Finding{{Severity: finding.SevHigh}}
	cases := []struct {
		name string
		fs   []finding.Finding
		gaps []finding.Gap
		t    threshold
		want int
	}{
		{"clear", nil, nil, threshold{severity: finding.SevHigh}, exitClear},
		{"findings", high, gaps, threshold{severity: finding.SevHigh}, exitFindings},
		{"incomplete", nil, gaps, threshold{severity: finding.SevHigh}, exitIncomplete},
		{"never asks nothing", nil, gaps, threshold{never: true}, exitClear},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := exitFor(c.fs, c.gaps, c.t); got != c.want {
				t.Fatalf("exitFor = %d, want %d", got, c.want)
			}
		})
	}
}

// cliQuiet sends stderr to the void for one test. parseArgs reports usage
// errors to the operator, and a table of them buries the test output.
func cliQuiet(t *testing.T) {
	t.Helper()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = devnull
	t.Cleanup(func() {
		os.Stderr = saved
		devnull.Close()
	})
}

func TestBuildSurvivesAShortResolution(t *testing.T) {
	pkgs := []finding.Package{
		{Name: "lodash", Ecosystem: "npm", Version: "4.17.20"},
		{Name: "hono", Ecosystem: "npm", Version: "4.0.0"},
	}
	if got, _ := build(pkgs, nil, nil); got != nil {
		t.Fatalf("build = %v, want nil — a query that answered for nothing must not be read past", got)
	}
}
