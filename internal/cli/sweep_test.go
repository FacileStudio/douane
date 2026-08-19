package cli

import (
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

	fa := buildFrom(a.pkgs, ids, vulns)
	fb := buildFrom(b.pkgs, ids, vulns)
	if len(fa) != 1 || len(fb) != 1 {
		t.Fatalf("findings = %d and %d, want one each — a shared package must be reported in both repos", len(fa), len(fb))
	}
	if fa[0].Target != "apps/api/bun.lock" || fb[0].Target != "package-lock.json" {
		t.Fatalf("targets = %q and %q, want each repo's own lockfile", fa[0].Target, fb[0].Target)
	}
}

func TestInventoriesSkipsProjectsWithoutPackages(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "empty", ".git", "HEAD"), "ref: refs/heads/main")
	write(t, filepath.Join(root, "real", "go.mod"), "module example.com/x\n\nrequire golang.org/x/crypto v0.31.0\n")

	repos := inventories([]string{filepath.Join(root, "empty"), filepath.Join(root, "real")})
	if len(repos) != 1 || repos[0].report.Name != "real" {
		t.Fatalf("inventories kept %d repos, want only the one declaring packages", len(repos))
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
