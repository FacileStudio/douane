package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/output"
	"github.com/FacileStudio/douane/internal/permit"
)

func cliStderr(t *testing.T, run func()) string {
	t.Helper()
	return capture(t, &os.Stderr, run)
}

func capture(t *testing.T, target **os.File, run func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := *target
	*target = w
	run()
	*target = saved
	w.Close()
	out, _ := io.ReadAll(r)
	r.Close()
	return string(out)
}

func TestScanRefusesAPermitWithoutExpiry(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "go.mod"), "module example.com/x\n\ngo 1.25.0\n")
	write(t, filepath.Join(dir, permit.FileName), permitMissingExpiry)
	code := exitClear
	stderr := cliStderr(t, func() { code = Run([]string{"scan", "-db", "", "-no-enrich", dir}) })
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d", code, exitUsage)
	}
	want := filepath.Join(dir, permit.FileName) + ":2: permit is missing expires"
	if !strings.Contains(stderr, want) {
		t.Fatalf("stderr = %q, want it to name the line: %q", stderr, want)
	}
}

func permitReport() output.Report {
	f := finding.Finding{ID: "GO-2026-1", Aliases: []string{"CVE-2026-9"}, Package: "golang.org/x/crypto",
		Ecosystem: "Go", Installed: "0.31.0", FixedIn: "0.35.0", Severity: finding.SevHigh, Target: "go.mod"}
	return output.Report{Target: "/repo", Packages: 1, Findings: []finding.Finding{f}, New: map[string]bool{}}
}

func renderLine(t *testing.T, r output.Report) (string, string) {
	t.Helper()
	var out, errw bytes.Buffer
	if err := output.WriteTo(&out, &errw, output.Line, output.LayoutFinding, r); err != nil {
		t.Fatal(err)
	}
	return out.String(), errw.String()
}

func TestAPermittedFindingLeavesTheOutputAndTheGate(t *testing.T) {
	today := permit.Today()
	r := permitReport()
	applyPermits(&r, []permit.Permit{{ID: "CVE-2026-9", Reason: "r", Expires: today.AddDate(0, 1, 0)}}, today)
	stdout, _ := renderLine(t, r)
	if stdout != "" || len(r.Permitted) != 1 {
		t.Fatalf("stdout = %q, permitted = %d; want the finding gone and listed as permitted", stdout, len(r.Permitted))
	}
	if code := permitExit(exitFor(r.Findings, r.Gaps, threshold{any: true}), r); code != exitClear {
		t.Fatalf("exit = %d, want %d under -fail any", code, exitClear)
	}
}

func TestALapsedPermitReturnsTheFindingAndFailsTheRun(t *testing.T) {
	today := permit.Today()
	r := permitReport()
	applyPermits(&r, []permit.Permit{{ID: "GO-2026-1", Reason: "r", Expires: today.AddDate(0, 0, -1), Line: 2}}, today)
	stdout, stderr := renderLine(t, r)
	if !strings.Contains(stdout, "GO-2026-1") || !strings.Contains(stdout, "permit=expired") {
		t.Fatalf("stdout = %q, want the finding back and marked", stdout)
	}
	if !strings.Contains(stderr, "douane: EXPIRED PERMIT: GO-2026-1") {
		t.Fatalf("stderr = %q, want the EXPIRED PERMIT note", stderr)
	}
	if code := permitExit(exitFor(r.Findings, r.Gaps, threshold{never: true}), r); code != exitFindings {
		t.Fatalf("exit = %d, want %d even under -fail never", code, exitFindings)
	}
}

func TestSweepPermitsApplyToTheirOwnRepoOnly(t *testing.T) {
	root := t.TempDir()
	body := "permits:\n  - id: GO-2026-1\n    reason: r\n    expires: " +
		permit.Today().AddDate(0, 1, 0).Format("2006-01-02") + "\n"
	write(t, filepath.Join(root, "a", permit.FileName), body)
	repos := []*repoScan{
		{report: output.Report{Target: filepath.Join(root, "a")}},
		{report: output.Report{Target: filepath.Join(root, "b")}},
	}
	attachPermits(repos, permit.Today())
	if len(repos[0].permits) != 1 || len(repos[1].permits) != 0 || len(repos[0].report.Gaps) != 0 {
		t.Fatalf("permits = %d and %d, want a's file to stay in a", len(repos[0].permits), len(repos[1].permits))
	}
}

const permitMissingExpiry = "permits:\n  - id: GO-2026-1\n    reason: not reachable\n"

const emptyLock = `{"lockfileVersion": 3, "packages": {"": {"name": "x"}}}`

type sweepJSON struct {
	Complete bool       `json:"complete"`
	Repos    []repoJSON `json:"repos"`
}

type repoJSON struct {
	Name     string        `json:"name"`
	Complete bool          `json:"complete"`
	Failed   bool          `json:"failed"`
	Gaps     []finding.Gap `json:"gaps"`
}

func runJSONSweep(t *testing.T, root string) (int, sweepJSON, string) {
	t.Helper()
	code := exitClear
	var stdout string
	stderr := cliStderr(t, func() {
		stdout = capture(t, &os.Stdout, func() {
			code = Run([]string{"sweep", "-db", "", "-no-enrich", "-format", "json", "-fail", "any", root})
		})
	})
	var got sweepJSON
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	return code, got, stderr
}

func checkPermitGapRepo(t *testing.T, r repoJSON, where string) {
	t.Helper()
	if r.Name == "good" {
		if !r.Complete || r.Failed || len(r.Gaps) != 0 {
			t.Fatalf("good = %+v, want it swept normally", r)
		}
		return
	}
	if r.Complete || !r.Failed || len(r.Gaps) != 1 || r.Gaps[0].Kind != finding.GapUnreadable ||
		r.Gaps[0].Subject != permit.FileName || !strings.Contains(r.Gaps[0].Detail, where) {
		t.Fatalf("bad = %+v, want one unreadable douane.yml gap naming the line", r)
	}
}

func TestSweepReportsAnInvalidPermitFileAsAGapAndCarriesOn(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "bad", "package-lock.json"), emptyLock)
	write(t, filepath.Join(root, "bad", permit.FileName), permitMissingExpiry)
	write(t, filepath.Join(root, "good", "package-lock.json"), emptyLock)
	code, got, stderr := runJSONSweep(t, root)
	if code != exitIncomplete {
		t.Fatalf("exit = %d, want %d: an invalid douane.yml leaves its repository incomplete", code, exitIncomplete)
	}
	where := filepath.Join(root, "bad", permit.FileName) + ":2: permit is missing expires"
	if !strings.Contains(stderr, where) {
		t.Fatalf("stderr = %q, want the file and line: %q", stderr, where)
	}
	if got.Complete || len(got.Repos) != 2 {
		t.Fatalf("complete = %v with %d repos, want an incomplete sweep of both", got.Complete, len(got.Repos))
	}
	for _, r := range got.Repos {
		checkPermitGapRepo(t, r, where)
	}
}

func TestSweepFindingsOutrankAnInvalidPermitFile(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "bad", permit.FileName), permitMissingExpiry)
	bad := &repoScan{report: output.Report{Name: "bad", Target: filepath.Join(root, "bad"), New: map[string]bool{}},
		pkgs: []finding.Package{{Name: "hono", Ecosystem: "npm", Version: "4.0.0"}}}
	good := &repoScan{report: permitReport()}
	cliStderr(t, func() { attachPermits([]*repoScan{bad, good}, permit.Today()) })
	if bad.pkgs != nil {
		t.Fatal("the repository with an invalid douane.yml kept its packages and would be scanned without its permits")
	}
	var sweep output.Sweep
	collect([]*repoScan{bad, good}, nil, &sweep, finding.FilterAll, "warn")
	if code := sweepExit(sweep, threshold{severity: finding.SevHigh}); code != exitFindings {
		t.Fatalf("exit = %d, want %d: findings at -fail outrank the gap", code, exitFindings)
	}
	if code := sweepExit(sweep, threshold{severity: finding.SevCritical}); code != exitIncomplete {
		t.Fatalf("exit = %d, want %d below -fail", code, exitIncomplete)
	}
}
