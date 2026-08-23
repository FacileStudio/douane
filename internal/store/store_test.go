package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
)

// stFindings builds n distinct findings, one per key, so a sweep saved with
// them can be told apart from its neighbours.
func stFindings(n int) []finding.Finding {
	out := make([]finding.Finding, 0, n)
	for i := range n {
		out = append(out, finding.Finding{
			ID:        "GO-" + string(rune('A'+i%26)),
			Package:   "pkg",
			Ecosystem: "Go",
			Installed: string(rune('a' + i%26)),
		})
	}
	return out
}

func stCount(t *testing.T, st *Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := st.db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestOpenAppliesTheConcurrencyPragmas(t *testing.T) {
	st := open(t)
	for _, c := range []struct{ pragma, want string }{
		{"journal_mode", "wal"},
		{"foreign_keys", "1"},
		{"busy_timeout", "5000"},
	} {
		var got string
		if err := st.db.QueryRow("PRAGMA " + c.pragma).Scan(&got); err != nil {
			t.Fatalf("PRAGMA %s: %v", c.pragma, err)
		}
		if got != c.want {
			t.Fatalf("%s = %q, want %q — the DSN parameters are not reaching the driver",
				c.pragma, got, c.want)
		}
	}
}

// TestOpenSurvivesAnAwkwardPath pins the escaping. The DSN is a URI now, so a
// database under a directory holding a question mark used to truncate it and
// lose every parameter without failing.
func TestOpenSurvivesAnAwkwardPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a b?c#d%e")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "douane.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open %q: %v", path, err)
	}
	defer st.Close()
	if err := st.Save("t", 1, stFindings(1)); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat %q: %v — the driver opened some other file", path, err)
	}
}

func TestSaveKeepsOnlyTheLastSweeps(t *testing.T) {
	st := open(t)
	for i := range keepSweeps + 5 {
		if err := st.Save("target", i, stFindings(3)); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	if got := stCount(t, st, `SELECT count(*) FROM sweeps WHERE target = ?`, "target"); got != keepSweeps {
		t.Fatalf("sweeps = %d, want %d — retention is not running", got, keepSweeps)
	}
	if got := stCount(t, st, `SELECT count(*) FROM findings`); got != keepSweeps*3 {
		t.Fatalf("findings = %d, want %d — the ON DELETE CASCADE is not firing, so _fk=1 is not applied",
			got, keepSweeps*3)
	}
	if got := stCount(t, st,
		`SELECT count(*) FROM findings WHERE sweep_id NOT IN (SELECT id FROM sweeps)`); got != 0 {
		t.Fatalf("orphan findings = %d, want 0", got)
	}
}

func TestPruneLeavesOtherTargetsAlone(t *testing.T) {
	st := open(t)
	if err := st.Save("kept", 1, stFindings(2)); err != nil {
		t.Fatalf("save: %v", err)
	}
	for i := range keepSweeps + 3 {
		if err := st.Save("churned", i, stFindings(1)); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	if got := stCount(t, st, `SELECT count(*) FROM sweeps WHERE target = ?`, "kept"); got != 1 {
		t.Fatalf("kept sweeps = %d, want 1 — retention crossed targets", got)
	}
	previous, err := st.PreviousKeys("kept")
	if err != nil {
		t.Fatalf("previous: %v", err)
	}
	if len(previous) != 2 {
		t.Fatalf("previous keys = %d, want 2", len(previous))
	}
}
