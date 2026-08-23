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

func outWriteTo(t *testing.T, f output.Format, r output.Report) (stdout, stderr string) {
	t.Helper()
	var out, errw bytes.Buffer
	if err := output.WriteTo(&out, &errw, f, r); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	return out.String(), errw.String()
}

// TestLineKeepsNotesOffStdout is the reason WriteTo exists: anything parsing
// the line format reads stdout, and a warning printed there is a finding as
// far as a naive parser is concerned.
func TestLineKeepsNotesOffStdout(t *testing.T) {
	stdout, stderr := outWriteTo(t, output.Line, outReport())
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
	for _, want := range []string{"douane: gap: ", "douane: warning: ", "Go:chi@5.0.0"} {
		if !strings.Contains(got, want) {
			t.Fatalf("Write = %q, want it to carry %q", got, want)
		}
	}
	if strings.Index(got, "douane: gap: ") > strings.Index(got, "Go:chi@5.0.0") {
		t.Fatal("notes print after the findings; a reader who stops early misses them")
	}
}

func TestTextRendersGapsDistinctlyFromFindings(t *testing.T) {
	stdout, stderr := outWriteTo(t, output.Text, outReport())
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
	stdout, _ := outWriteTo(t, output.Text, r)
	if strings.Contains(stdout, "clear") {
		t.Fatalf("text = %q, want no claim of clear over an unreadable lockfile", stdout)
	}
	if !strings.Contains(stdout, "incomplete") {
		t.Fatalf("text = %q, want it to say the scan is incomplete", stdout)
	}
}
