package output_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/output"
)

func outFinding(id string) finding.Finding {
	return finding.Finding{ID: id, Package: "chi", Ecosystem: "Go",
		Installed: "5.0.0", FixedIn: "5.0.12", Severity: finding.SevHigh, Target: "go.mod"}
}

// outReport is a scan holding one finding it has never seen before, one gap
// and one warning: every channel of the report at once.
func outReport() output.Report {
	f := outFinding("GO-1")
	return output.Report{
		Name: "api", Target: "/repo", Packages: 12,
		Findings: []finding.Finding{f},
		New:      map[string]bool{f.Key(): true},
		Gaps:     []finding.Gap{{Kind: finding.GapUpstream, Subject: "osv", Detail: "429"}},
		Warnings: []string{"KEV feed unavailable"},
	}
}

func outWriteTo(t *testing.T, f output.Format, l output.Layout, r output.Report) (stdout, stderr string) {
	t.Helper()
	var out, errw bytes.Buffer
	if err := output.WriteTo(&out, &errw, f, l, r); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	return out.String(), errw.String()
}

// TestLineKeepsNotesOffStdout is the reason WriteTo exists: anything parsing
// the line format reads stdout, and a warning printed there is a finding as
// far as a naive parser is concerned.
func TestLineKeepsNotesOffStdout(t *testing.T) {
	stdout, stderr := outWriteTo(t, output.Line, output.LayoutFix, outReport())
	if strings.Contains(stdout, "warning") || strings.Contains(stdout, "gap") {
		t.Fatalf("stdout = %q, want findings only", stdout)
	}
	if lines := strings.Count(stdout, "\n"); lines != 1 {
		t.Fatalf("stdout has %d lines, want 1 finding", lines)
	}
	for _, want := range []string{"douane: gap: upstream: osv: 429", "douane: warning: KEV feed unavailable"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr = %q, want it to carry %q", stderr, want)
		}
	}
}

// TestWriteStillPutsEverythingOnOneWriter pins the old contract: Write is what
// internal/cli calls today, and it must not start losing warnings.
func TestWriteStillPutsEverythingOnOneWriter(t *testing.T) {
	var buf bytes.Buffer
	if err := output.Write(&buf, output.Line, outReport()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := buf.String()
	for _, want := range []string{"douane: gap: ", "douane: warning: ", "Go:chi@"} {
		if !strings.Contains(got, want) {
			t.Fatalf("Write = %q, want it to carry %q", got, want)
		}
	}
	if strings.Index(got, "douane: gap: ") > strings.Index(got, "Go:chi@") {
		t.Fatal("notes print after the findings; a reader who stops early misses them")
	}
}

// TestLineByFindingIsTheHistoricalShape pins the flat bytes exactly: anything
// that parsed douane's line output before grouping existed must read the same
// stream after passing -by finding, with no migration.
func TestLineByFindingIsTheHistoricalShape(t *testing.T) {
	stdout, _ := outWriteTo(t, output.Line, output.LayoutFinding, outReport())
	want := "Go:chi@5.0.0: high: GO-1 [go.mod epss=0.0000 kev=false fix=5.0.12]\n"
	if stdout != want {
		t.Fatalf("stdout = %q, want %q", stdout, want)
	}
}

func TestLineByFixPrintsOneLinePerAction(t *testing.T) {
	r := outReport()
	f2 := outFinding("GO-2")
	f2.Installed = "4.11.0"
	r.Findings = append(r.Findings, f2)
	stdout, _ := outWriteTo(t, output.Line, output.LayoutFix, r)
	if lines := strings.Count(stdout, "\n"); lines != 1 {
		t.Fatalf("stdout has %d lines, want one per fix, got %q", lines, stdout)
	}
	for _, want := range []string{"Go:chi@5.0.12: 2 findings", "worst=GO-1", "fix=5.0.12"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout = %q, want it to carry %q", stdout, want)
		}
	}
}

// TestTextByFixCollapsesRepeatedBumps is v1.4's exit criterion in miniature:
// the same upgrade advised against several installed versions is one decision,
// so it prints once with a count instead of once per finding.
func TestTextByFixCollapsesRepeatedBumps(t *testing.T) {
	r := outReport()
	f2 := outFinding("GO-2")
	f2.Installed = "4.11.0"
	r.Findings = append(r.Findings, f2)
	stdout, _ := outWriteTo(t, output.Text, output.LayoutFix, r)
	if got := strings.Count(stdout, "chi"); got != 1 {
		t.Fatalf("text names chi %d times, want one action block:\n%s", got, stdout)
	}
	// A buffer is not a terminal and declares no locale, so it renders with the
	// ASCII glyph set: "->", not "→". Same rule as filet.
	for _, want := range []string{"2 findings", "4.11.0, 5.0.0 -> 5.0.12", "1 fix", "2 high"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("text = %q, want it to carry %q", stdout, want)
		}
	}
}

// TestTextByFindingKeepsOneBlockPerFinding guards the escape hatch: the flat
// view must still exist verbatim for whoever needs the old report.
func TestTextByFindingKeepsOneBlockPerFinding(t *testing.T) {
	r := outReport()
	f2 := outFinding("GO-2")
	f2.Installed = "4.11.0"
	r.Findings = append(r.Findings, f2)
	stdout, _ := outWriteTo(t, output.Text, output.LayoutFinding, r)
	if got := strings.Count(stdout, "chi"); got != 2 {
		t.Fatalf("flat text names chi %d times, want one block per finding:\n%s", got, stdout)
	}
}

func TestTextRendersGapsDistinctlyFromFindings(t *testing.T) {
	stdout, stderr := outWriteTo(t, output.Text, output.LayoutFix, outReport())
	if stderr != "" {
		t.Fatalf("stderr = %q, want the text form to stay one narrative", stderr)
	}
	if !strings.Contains(stdout, "  ? upstream: osv: 429") {
		t.Fatalf("text = %q, want the gap marked with ?", stdout)
	}
	if !strings.Contains(stdout, "  ! KEV feed unavailable") {
		t.Fatalf("text = %q, want the warning marked with !", stdout)
	}
}

// TestTextWillNotCallAnIncompleteScanClear is the whole point of a gap: a scan
// that could not finish has not established that there is nothing to find.
func TestTextWillNotCallAnIncompleteScanClear(t *testing.T) {
	r := output.Report{Target: "/repo", Packages: 12,
		Gaps: []finding.Gap{{Kind: finding.GapUnreadable, Subject: "bun.lock", Detail: "truncated"}}}
	stdout, _ := outWriteTo(t, output.Text, output.LayoutFix, r)
	if strings.Contains(stdout, "clear") {
		t.Fatalf("text = %q, want no claim of clear over an unreadable lockfile", stdout)
	}
	if !strings.Contains(stdout, "incomplete") {
		t.Fatalf("text = %q, want it to say the scan is incomplete", stdout)
	}
}
