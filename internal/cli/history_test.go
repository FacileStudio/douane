package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/permit"
	"github.com/FacileStudio/douane/internal/store"
)

func flawNamedBoth(reportedAs string) finding.Finding {
	f := finding.Finding{Ecosystem: "npm", Package: "devalue", Installed: "5.8.0"}
	if reportedAs == "CVE" {
		f.ID, f.Aliases = "CVE-2026-123565", []string{"GHSA-mcm9-63f2-9j32"}
		return f
	}
	f.ID, f.Aliases = "GHSA-mcm9-63f2-9j32", []string{"CVE-2026-123565"}
	return f
}

func TestSeenBeforeSurvivesAFlipInEitherDirection(t *testing.T) {
	for _, tc := range []struct{ was, now string }{{"CVE", "GHSA"}, {"GHSA", "CVE"}} {
		yesterday := flawNamedBoth(tc.was)
		previous := map[string]bool{yesterday.Key(): true}

		if !seenBefore(previous, flawNamedBoth(tc.now)) {
			t.Fatalf("reported as %s then %s: the flaw read as new", tc.was, tc.now)
		}
	}
}

func TestSeenBeforeReadsKeysWrittenUnderTheOldScheme(t *testing.T) {
	today := flawNamedBoth("CVE")
	legacy := map[string]bool{today.KeyAs("GHSA-mcm9-63f2-9j32"): true}

	if !seenBefore(legacy, today) {
		t.Fatal("a history keyed by the GHSA name made the finding new")
	}
}

func TestSeenBeforeStillCallsAnUnknownFlawNew(t *testing.T) {
	previous := map[string]bool{flawNamedBoth("CVE").Key(): true}
	other := finding.Finding{Ecosystem: "npm", Package: "devalue", Installed: "5.8.0", ID: "CVE-2026-999"}

	if seenBefore(previous, other) {
		t.Fatal("an unrelated flaw was treated as already seen")
	}
}

func TestASkippedRepoKeepsItsPreviousHistory(t *testing.T) {
	root, db := t.TempDir(), filepath.Join(t.TempDir(), "douane.db")
	for _, tc := range []struct{ repo, file, body string }{
		{"permit", permit.FileName, permitMissingExpiry},
		{"lockfile", "package-lock.json", "{not json"},
	} {
		repo := filepath.Join(root, tc.repo)
		write(t, filepath.Join(repo, ".git", "HEAD"), "ref: refs/heads/main")
		write(t, filepath.Join(repo, tc.file), tc.body)
		st, err := store.Open(db)
		if err != nil {
			t.Fatal(err)
		}
		held := flawNamedBoth("CVE")
		if err := st.Save(repo, 3, []finding.Finding{held}); err != nil {
			t.Fatal(err)
		}
		st.Close()
		cliStderr(t, func() {
			capture(t, &os.Stdout, func() { Run([]string{"sweep", "-db", db, "-no-enrich", "-format", "json", root}) })
		})
		st, _ = store.Open(db)
		previous, err := st.PreviousKeys(repo)
		st.Close()
		if err != nil || !previous[held.Key()] {
			t.Fatalf("%s: previous = %v, %v; a skipped repo overwrote its history", tc.repo, previous, err)
		}
	}
}
