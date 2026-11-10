package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/output"
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

func recordOver(t *testing.T, gap finding.Gap) map[string]bool {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "douane.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Save("/app", 3, []finding.Finding{flawNamedBoth("CVE")}); err != nil {
		t.Fatal(err)
	}
	other := finding.Finding{Ecosystem: "npm", Package: "devalue", Installed: "5.8.0", ID: "CVE-2026-999"}
	report := output.Report{Target: "/app", Packages: 3, New: map[string]bool{},
		Findings: []finding.Finding{other}, Gaps: []finding.Gap{gap}}
	record(st, &report)
	previous, err := st.PreviousKeys("/app")
	if err != nil {
		t.Fatal(err)
	}
	return previous
}

func TestAGapThatCanHideFindingsKeepsThePreviousHistory(t *testing.T) {
	held := flawNamedBoth("CVE").Key()
	for _, gap := range []finding.Gap{
		{Kind: finding.GapUpstream, Subject: "golang.org/x/crypto", Detail: "osv query failed"},
		{Kind: finding.GapUnreadable, Subject: "web/package-lock.json", Detail: "bad json"},
		{Kind: finding.GapUnsupported, Subject: "pnpm-lock.yaml", Detail: "unsupported"},
		{Kind: finding.GapUnresolved, Subject: "GHSA-xxxx", Detail: "fetch failed"},
	} {
		if previous := recordOver(t, gap); !previous[held] || len(previous) != 1 {
			t.Errorf("%s: previous = %v, want the earlier row kept", gap.Kind, previous)
		}
	}
}

func TestAGapThatHidesNothingStillWritesTheHistory(t *testing.T) {
	for _, gap := range []finding.Gap{
		{Kind: finding.GapSeverity, Subject: "CVE-2026-999", Detail: "unrated", Advisory: "CVE-2026-999"},
		{Kind: finding.GapRange, Subject: "devalue", Detail: "commit ranges", Advisory: "CVE-2026-999"},
		{Kind: finding.GapUpstream, Subject: "epss", Detail: "scores unavailable", Annotation: true},
		{Kind: finding.GapUnresolved, Subject: "Dockerfile", Detail: "untagged image", Annotation: true},
	} {
		if previous := recordOver(t, gap); previous[flawNamedBoth("CVE").Key()] || len(previous) != 1 {
			t.Errorf("%s: previous = %v, want this run's row written", gap.Kind, previous)
		}
	}
}
