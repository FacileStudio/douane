package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/osv"
	"github.com/FacileStudio/douane/internal/output"
)

func TestDiscoverFindsCheckoutsAndSkipsTheRest(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "checkout", ".git", "HEAD"), "ref: refs/heads/main")
	write(t, filepath.Join(root, "lockfile-only", "package-lock.json"), "{}")
	write(t, filepath.Join(root, "prose", "README.md"), "# hello")
	write(t, filepath.Join(root, ".hidden", ".git", "HEAD"), "ref: refs/heads/main")

	dirs, err := discover(root)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	var names []string
	for _, d := range dirs {
		names = append(names, filepath.Base(d))
	}
	if len(names) != 2 || names[0] != "checkout" || names[1] != "lockfile-only" {
		t.Fatalf("discover = %v, want [checkout lockfile-only]", names)
	}
}

func TestSharedResolutionKeepsEveryRepoFindings(t *testing.T) {
	shared := finding.Package{Name: "hono", Ecosystem: "npm", Version: "4.0.0"}
	a := &repoScan{pkgs: []finding.Package{
		{Name: "hono", Ecosystem: "npm", Version: "4.0.0", Source: "apps/api/bun.lock"},
	}}
	b := &repoScan{pkgs: []finding.Package{
		{Name: "hono", Ecosystem: "npm", Version: "4.0.0", Source: "package-lock.json"},
		{Name: "vite", Ecosystem: "npm", Version: "7.3.1", Source: "package-lock.json"},
	}}

	if got := union([]*repoScan{a, b}); len(got) != 2 {
		t.Fatalf("union = %d packages, want 2 — the shared package was not deduped", len(got))
	}
	ids := map[string][]string{
		pkgKey(shared): {"CVE-2026-1"},
	}
	vulns := map[string]osv.Vuln{"CVE-2026-1": {ID: "CVE-2026-1", Summary: "boom"}}

	fa, _ := buildFrom(a.pkgs, ids, vulns)
	fb, _ := buildFrom(b.pkgs, ids, vulns)
	if len(fa) != 1 || len(fb) != 1 {
		t.Fatalf("findings = %d and %d, want one each — a shared package must be reported in both repos", len(fa), len(fb))
	}
	if fa[0].Target != "apps/api/bun.lock" || fb[0].Target != "package-lock.json" {
		t.Fatalf("targets = %q and %q, want each repo's own lockfile", fa[0].Target, fb[0].Target)
	}
}

func TestInventoriesKeepsProjectsWithoutPackages(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "empty", ".git", "HEAD"), "ref: refs/heads/main")
	write(t, filepath.Join(root, "real", "go.mod"), "module example.com/x\n\nrequire golang.org/x/crypto v0.31.0\n")

	repos := inventories([]string{filepath.Join(root, "empty"), filepath.Join(root, "real")})
	if len(repos) != 2 {
		t.Fatalf("inventories kept %d repos, want 2 — a repo douane cannot read must still be reported", len(repos))
	}
	if repos[0].report.Name != "empty" || repos[0].report.Packages != 0 {
		t.Fatalf("repo 0 = %q with %d packages, want empty with 0",
			repos[0].report.Name, repos[0].report.Packages)
	}
	if repos[1].report.Packages == 0 {
		t.Fatal("the repo declaring packages reported none")
	}
}

func TestSweepCarriesEveryRepoGap(t *testing.T) {
	r := &repoScan{report: output.Report{Name: "unsupported", New: map[string]bool{}}}
	r.report.Gaps = []finding.Gap{{
		Kind:    finding.GapUnsupported,
		Subject: "unsupported",
		Detail:  "composer.lock is not an ecosystem douane reads",
	}}
	var sweep output.Sweep
	collect([]*repoScan{r}, nil, &sweep)

	if got := sweep.AllGaps(); len(got) != 1 || got[0].Kind != finding.GapUnsupported {
		t.Fatalf("AllGaps = %v, want the repo gap — a gap that never reaches the sweep cannot set the exit code", got)
	}
	if code := sweepExit(sweep, threshold{severity: finding.SevHigh}); code != exitIncomplete {
		t.Fatalf("sweepExit = %d, want %d", code, exitIncomplete)
	}
}

func TestSortReposPutsTheWorstFirst(t *testing.T) {
	quiet := output.Report{Name: "quiet"}
	low := output.Report{Name: "low", Findings: []finding.Finding{{Severity: finding.SevLow}}}
	kev := output.Report{Name: "kev", Findings: []finding.Finding{{Severity: finding.SevLow}}}
	kev.Findings[0].Exploit.KEV = true

	repos := []output.Report{quiet, low, kev}
	output.SortRepos(repos)
	if repos[0].Name != "kev" || repos[2].Name != "quiet" {
		t.Fatalf("order = %s %s %s, want kev low quiet", repos[0].Name, repos[1].Name, repos[2].Name)
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanOneCallsAnEmptyTargetAGap(t *testing.T) {
	report, code := scanOne(context.Background(), options{path: t.TempDir()}, nil)
	if code != exitClear {
		t.Fatalf("code = %d, want %d", code, exitClear)
	}
	if len(report.Gaps) != 1 || report.Gaps[0].Kind != finding.GapUnsupported {
		t.Fatalf("gaps = %v, want one unsupported gap: finding nothing to scan is not the same as finding nothing wrong",
			report.Gaps)
	}
	if got := exitFor(report.Findings, report.Gaps, threshold{severity: finding.SevHigh}); got != exitIncomplete {
		t.Fatalf("exitFor = %d, want %d — the wrong directory must not report clean", got, exitIncomplete)
	}
	if got := exitFor(report.Findings, report.Gaps, threshold{never: true}); got != exitClear {
		t.Fatalf("exitFor under -fail never = %d, want %d", got, exitClear)
	}
}
