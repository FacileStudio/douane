package permit_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/permit"
)

var today = time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)

const valid = `# permits for the api
permits:
  - id: GHSA-aaaa-bbbb-cccc
    package: golang.org/x/crypto
    reason: no fix published, not reachable from the API  # see issue#12
    expires: 2027-01-31
  - id: "CVE-2026-1"
    reason: 'the build never runs it: it''s a dev tool'
    expires: "2026-11-20"
`

func TestParseReadsEveryEntry(t *testing.T) {
	got, err := permit.Parse([]byte(valid), today)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Parse = %d permits, want 2", len(got))
	}
	first, second := got[0], got[1]
	if first.ID != "GHSA-aaaa-bbbb-cccc" || first.Package != "golang.org/x/crypto" || first.Line != 3 {
		t.Fatalf("first = %+v", first)
	}
	if first.Reason != "no fix published, not reachable from the API" {
		t.Fatalf("reason = %q, want the comment stripped", first.Reason)
	}
	if second.Reason != "the build never runs it: it's a dev tool" || second.Package != "" {
		t.Fatalf("second = %+v", second)
	}
	if !second.Expires.Equal(time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("expires = %s", second.Expires)
	}
}

func TestParseRefusesWithTheLine(t *testing.T) {
	cases := []struct {
		name, doc string
		line      int
		msg       string
	}{
		{"no expires", "permits:\n  - id: X\n    reason: r\n", 2, "missing expires"},
		{"no reason", "permits:\n\n  - id: X\n    expires: 2027-01-01\n", 3, "missing reason"},
		{"too far", "permits:\n  - id: X\n    reason: r\n    expires: 2027-11-11\n", 4, "365 days"},
		{"bad date", "permits:\n  - id: X\n    reason: r\n    expires: 31/01/2027\n", 4, "not a date"},
		{"unknown key", "permits:\n  - id: X\n    expire: 2027-01-01\n", 3, "unknown key"},
		{"empty value", "permits:\n  - id: X\n    reason:\n", 3, "reason is empty"},
		{"twice", "permits:\n  - id: X\n    id: Y\n", 3, "set twice"},
		{"tabs", "permits:\n\t- id: X\n", 2, "tabs"},
		{"other root", "ignore:\n  - X\n", 1, "only permits"},
		{"block scalar", "permits:\n  - id: X\n    reason: >\n", 3, "unsupported"},
		{"misaligned", "permits:\n  - id: X\n   reason: r\n", 3, "line up"},
		{"colon", "permits:\n  - id: X\n    reason: a: b\n", 3, "colon"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := permit.Parse([]byte(c.doc), today)
			var pe *permit.Error
			if !errors.As(err, &pe) || pe.Line != c.line || !strings.Contains(pe.Msg, c.msg) {
				t.Fatalf("Parse error = %v, want line %d saying %q", err, c.line, c.msg)
			}
		})
	}
}

func TestParseAllowsAnEmptyList(t *testing.T) {
	for _, doc := range []string{"", "# nothing yet\n", "permits:\n", "permits: []\n"} {
		if got, err := permit.Parse([]byte(doc), today); err != nil || len(got) != 0 {
			t.Fatalf("Parse(%q) = %v, %v; want no permits and no error", doc, got, err)
		}
	}
}

func TestLoadNamesTheFileAndLine(t *testing.T) {
	dir := t.TempDir()
	body := "permits:\n  - id: X\n    reason: r\n"
	if err := os.WriteFile(filepath.Join(dir, permit.FileName), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := permit.Load(dir, today)
	want := filepath.Join(dir, permit.FileName) + ":2: permit is missing expires"
	if err == nil || err.Error() != want {
		t.Fatalf("Load error = %v, want %q", err, want)
	}
	if got, err := permit.Load(t.TempDir(), today); err != nil || got != nil {
		t.Fatalf("Load without a file = %v, %v; want nothing", got, err)
	}
}

func flaw() finding.Finding {
	return finding.Finding{ID: "GO-2026-1", Aliases: []string{"GHSA-aaaa-bbbb-cccc"},
		Package: "golang.org/x/crypto", Ecosystem: "Go", Installed: "0.31.0"}
}

func TestApplyPermitsAValidEntry(t *testing.T) {
	p := permit.Permit{ID: "GHSA-aaaa-bbbb-cccc", Reason: "r", Expires: today}
	out := permit.Apply([]finding.Finding{flaw()}, []permit.Permit{p}, today)
	if len(out.Kept) != 0 || len(out.Permitted) != 1 || len(out.Expired) != 0 {
		t.Fatalf("outcome = %+v, want the finding permitted on its last valid day", out)
	}
}

func TestApplyReturnsAFindingWhenItsPermitLapses(t *testing.T) {
	p := permit.Permit{ID: "GHSA-aaaa-bbbb-cccc", Reason: "r", Expires: today.AddDate(0, 0, -1), Line: 2}
	out := permit.Apply([]finding.Finding{flaw()}, []permit.Permit{p}, today)
	if len(out.Kept) != 1 || len(out.Expired) != 1 || len(out.Permitted) != 0 {
		t.Fatalf("outcome = %+v, want the finding kept and marked expired", out)
	}
	notes := permit.Notes(out, []permit.Permit{p}, today)
	if len(notes) != 1 || !strings.HasPrefix(notes[0], "EXPIRED PERMIT: GHSA-aaaa-bbbb-cccc") {
		t.Fatalf("notes = %q, want one EXPIRED PERMIT line", notes)
	}
}

func TestApplyPrefersAValidPermitAndNarrowsByPackage(t *testing.T) {
	old := permit.Permit{ID: "GO-2026-1", Expires: today.AddDate(0, -1, 0)}
	other := permit.Permit{ID: "GO-2026-1", Package: "golang.org/x/net", Expires: today}
	renewed := permit.Permit{ID: "GO-2026-1", Package: "golang.org/x/crypto", Expires: today}
	out := permit.Apply([]finding.Finding{flaw()}, []permit.Permit{old, other, renewed}, today)
	if len(out.Permitted) != 1 || out.Permitted[0].Permit.Package != "golang.org/x/crypto" {
		t.Fatalf("outcome = %+v, want the renewed permit for this package to win", out)
	}
	if len(out.Unused) != 1 || out.Unused[0].Package != "" {
		t.Fatalf("unused = %+v, want the superseded lapsed entry flagged for removal", out.Unused)
	}
}

func TestNotesListPermitsAboutToLapse(t *testing.T) {
	soon := permit.Permit{ID: "A", Expires: today.AddDate(0, 0, 14), Line: 2}
	later := permit.Permit{ID: "B", Expires: today.AddDate(0, 0, 15), Line: 6}
	lapsed := permit.Permit{ID: "C", Expires: today.AddDate(0, 0, -3), Line: 10}
	all := []permit.Permit{soon, later, lapsed}
	notes := permit.Notes(permit.Apply(nil, all, today), all, today)
	want := []string{
		"permit C lapsed 2026-11-07 and suppresses nothing, remove it (douane.yml:10)",
		"permit A expires 2026-11-24, in 14 days (douane.yml:2)",
	}
	if strings.Join(notes, "\n") != strings.Join(want, "\n") {
		t.Fatalf("notes = %q, want %q", notes, want)
	}
}
