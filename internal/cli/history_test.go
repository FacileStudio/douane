package cli

import (
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
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
