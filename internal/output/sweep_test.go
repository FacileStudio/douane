package output_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/output"
)

// outSweep is a fleet run where one repository is clean and the other could
// not be read at all, which is the case a sweep must never call clear.
func outSweep() output.Sweep {
	gap := finding.Gap{Kind: finding.GapUnsupported, Subject: "web",
		Detail: "no lockfile douane can read"}
	api := output.Report{Name: "api", Packages: 40}
	web := output.Report{Name: "web", Gaps: []finding.Gap{gap}}
	return output.Sweep{Root: "/fleet", Repos: []output.Report{api, web}}
}

func outWriteSweep(t *testing.T, f output.Format, s output.Sweep) (stdout, stderr string) {
	return outWriteSweepLayout(t, f, output.LayoutFinding, s)
}

func outWriteSweepLayout(t *testing.T, f output.Format, l output.Layout, s output.Sweep) (stdout, stderr string) {
	t.Helper()
	var out, errw bytes.Buffer
	if err := output.WriteSweepTo(&out, &errw, f, l, s); err != nil {
		t.Fatalf("WriteSweepTo: %v", err)
	}
	return out.String(), errw.String()
}

func TestSweepTextWillNotCallAnIncompleteFleetClear(t *testing.T) {
	stdout, _ := outWriteSweep(t, output.Text, outSweep())
	if strings.HasPrefix(stdout, "clear — ") {
		t.Fatalf("sweep = %q, want no claim of clear while a repo could not be read", stdout)
	}
	if !strings.Contains(stdout, "  ? unsupported: web: no lockfile douane can read") {
		t.Fatalf("sweep = %q, want the gap rendered under its repo", stdout)
	}
	if !strings.Contains(stdout, "1 incomplete") {
		t.Fatalf("sweep = %q, want the tail to count the incomplete repo", stdout)
	}
}

// TestSweepTextStaysSilentWhenHealthy is the calibration target: a sweep over
// a healthy fleet is one line, and adding gaps must not have cost that.
func TestSweepTextStaysSilentWhenHealthy(t *testing.T) {
	s := output.Sweep{Root: "/fleet", Repos: []output.Report{{Name: "api", Packages: 40}}}
	stdout, _ := outWriteSweep(t, output.Text, s)
	if stdout != "clear — 1 repos, 40 packages, nothing held\n" {
		t.Fatalf("sweep = %q, want the single clear line", stdout)
	}
}

func TestSweepLineTagsNotesWithTheirRepo(t *testing.T) {
	stdout, stderr := outWriteSweep(t, output.Line, outSweep())
	if stdout != "" {
		t.Fatalf("stdout = %q, want nothing: no repo held a finding", stdout)
	}
	if !strings.Contains(stderr, "douane: gap: web: unsupported: web:") {
		t.Fatalf("stderr = %q, want the gap tagged with its repo", stderr)
	}
}

// fleetSweep is two repos holding the same advisory at different versions:
// the case where per-repo reporting says the same bump twice.
func fleetSweep() output.Sweep {
	mk := func(name, installed string) output.Report {
		f := finding.Finding{ID: "GO-1", Package: "chi", Ecosystem: "Go",
			Installed: installed, FixedIn: "5.0.12", Severity: finding.SevHigh,
			Target: name + "/go.mod"}
		return output.Report{Name: name, Packages: 10,
			Findings: []finding.Finding{f}}
	}
	return output.Sweep{Root: "/fleet", Repos: []output.Report{mk("api", "5.0.0"), mk("web", "4.11.0")}}
}

// TestSweepLineByFixIsOneLinePerFix is v1.4's exit criterion at fleet scale in
// miniature: N repos sharing one pending upgrade print one line, not N.
func TestSweepLineByFixIsOneLinePerFix(t *testing.T) {
	stdout, _ := outWriteSweepLayout(t, output.Line, output.LayoutFix, fleetSweep())
	if lines := strings.Count(stdout, "\n"); lines != 1 {
		t.Fatalf("stdout has %d lines, want 1:\n%s", lines, stdout)
	}
	for _, want := range []string{"Go:chi@5.0.12: 2 findings in 2 targets", "fix=5.0.12"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout = %q, want it to carry %q", stdout, want)
		}
	}
}

func TestSweepTextByFixKeepsRepoGapsVisible(t *testing.T) {
	s := fleetSweep()
	s.Repos = append(s.Repos, output.Report{Name: "opaque",
		Gaps: []finding.Gap{{Kind: finding.GapUnsupported, Subject: "web",
			Detail: "no lockfile douane can read"}}})
	stdout, _ := outWriteSweepLayout(t, output.Text, output.LayoutFix, s)
	if !strings.Contains(stdout, "opaque:\n  ? unsupported: web:") {
		t.Fatalf("text = %q, want the unreadable repo named under its gap", stdout)
	}
	if !strings.Contains(stdout, "2 findings across 2 repos, 1 fix clears them") {
		t.Fatalf("text = %q, want the grouped headline", stdout)
	}
}

func TestSweepTextByFindingKeepsPerRepoBlocks(t *testing.T) {
	stdout, _ := outWriteSweepLayout(t, output.Text, output.LayoutFinding, fleetSweep())
	if got := strings.Count(stdout, "— 1 held out of 10 packages"); got != 2 {
		t.Fatalf("text has %d repo blocks, want one per holding repo:\n%s", got, stdout)
	}
}

func TestSweepJSONVersionsTheRootOnly(t *testing.T) {
	stdout, _ := outWriteSweep(t, output.JSON, outSweep())
	var doc struct {
		SchemaVersion string `json:"schema_version"`
		Complete      bool   `json:"complete"`
		Repos         []struct {
			SchemaVersion string        `json:"schema_version"`
			Name          string        `json:"name"`
			Gaps          []finding.Gap `json:"gaps"`
		} `json:"repos"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("decode %s: %v", stdout, err)
	}
	if doc.SchemaVersion != output.SchemaVersion {
		t.Fatalf("schema_version = %q, want %q", doc.SchemaVersion, output.SchemaVersion)
	}
	if doc.Complete {
		t.Fatal("complete = true while a repo carries a gap")
	}
	if len(doc.Repos) != 2 || doc.Repos[0].SchemaVersion != "" {
		t.Fatalf("repos = %+v, want two, unversioned", doc.Repos)
	}
	if len(doc.Repos[1].Gaps) != 1 {
		t.Fatalf("web gaps = %+v, want the one it reported", doc.Repos[1].Gaps)
	}
}
