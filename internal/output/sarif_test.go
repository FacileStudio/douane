package output_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/output"
)

func sarifFixture() output.Report {
	high := outFinding("GHSA-aaaa-bbbb-cccc")
	high.Summary = "header smuggling"
	same := high
	same.Installed, same.Target = "4.11.0", "apps/api/go.mod"
	medium := outFinding("GO-2026-2")
	medium.Severity, medium.FixedIn = finding.SevMedium, ""
	low := outFinding("RUSTSEC-2026-1")
	low.Severity, low.Package, low.Ecosystem, low.Target = finding.SevUnknown, "time", "crates.io", "Cargo.lock"
	r := outReport()
	r.Findings = []finding.Finding{high, same, medium, low}
	r.Expired = map[string]bool{medium.Key(): true}
	return r
}

func TestSARIFMatchesTheGolden(t *testing.T) {
	stdout, stderr := outWriteTo(t, output.SARIF, output.LayoutFix, sarifFixture())
	if stderr == "" {
		t.Fatal("stderr is empty, want the gap and warning there and not in the SARIF")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("sarif is not json: %v", err)
	}
	golden := filepath.Join("testdata", "scan.sarif")
	if os.Getenv("DOUANE_UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(golden, []byte(stdout), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != string(want) {
		t.Fatalf("sarif drifted from %s:\n%s", golden, stdout)
	}
}

func TestSARIFSweepPrefixesEachRepo(t *testing.T) {
	stdout, _ := outWriteSweep(t, output.SARIF, fleetSweep())
	if !json.Valid([]byte(stdout)) {
		t.Fatalf("sarif is not json: %s", stdout)
	}
	for _, want := range []string{`"uri": "api/api/go.mod"`, `"uri": "web/web/go.mod"`,
		`"primaryLocationLineHash": "api/Go|chi|5.0.0|GO-1"`} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("sarif = %s, want %s", stdout, want)
		}
	}
}
