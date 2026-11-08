package finding

import "testing"

func TestRankPutsKnownExploitedFirst(t *testing.T) {
	fs := []Finding{
		{ID: "CVE-1", Severity: SevCritical, Exploit: Exploit{EPSS: 0.9}},
		{ID: "CVE-2", Severity: SevLow, Exploit: Exploit{EPSS: 0.01, KEV: true}},
	}
	Rank(fs)
	if fs[0].ID != "CVE-2" {
		t.Fatalf("first = %s, want CVE-2: a low-severity known-exploited flaw outranks a critical nobody exploits", fs[0].ID)
	}
}

func TestHasFixDistinguishesNoFixFromUntakenFix(t *testing.T) {
	if (Finding{FixedIn: ""}).HasFix() {
		t.Fatal("empty FixedIn must report no fix available")
	}
	if !(Finding{FixedIn: "1.2.3"}).HasFix() {
		t.Fatal("a set FixedIn must report a fix available")
	}
}

func TestFilterInformationalKeepsRealVulnerabilities(t *testing.T) {
	fs := []Finding{
		{ID: "CVE-1", Severity: SevHigh},
		{ID: "RUSTSEC-2025-0010", Informational: "unmaintained"},
		{ID: "RUSTSEC-2025-0002", Informational: "unsound"},
	}
	kept := FilterInformational(fs, true)
	if len(kept) != 1 || kept[0].ID != "CVE-1" {
		t.Fatalf("kept %v, want only the scoring vulnerability", kept)
	}
}

func TestFilterInformationalKeepsEverythingByDefault(t *testing.T) {
	fs := []Finding{{ID: "RUSTSEC-2025-0010", Informational: "unmaintained"}}
	if got := FilterInformational(fs, false); len(got) != 1 {
		t.Fatalf("kept %v, want everything — ignore is opt-in, never the default", got)
	}
}

// TestSameLine pins the boundary a rebuild claim rests on: only a fix on the
// line the image already builds from is reachable without editing a version.
func TestSameLine(t *testing.T) {
	cases := []struct {
		buildLine, fixedIn string
		want               bool
	}{
		{"1.25", "1.25.13", true},
		{"1.25", "1.25.0", true},
		{"1.25", "1.26.1", false},
		{"1.25", "1.24.13", false},
		{"", "1.25.13", false},
		{"1.25", "", false},
	}
	for _, c := range cases {
		if got := SameLine(c.buildLine, c.fixedIn); got != c.want {
			t.Fatalf("build line %q against fix %q = %v, want %v",
				c.buildLine, c.fixedIn, got, c.want)
		}
	}
}

func TestKeyIgnoresWhichAliasWon(t *testing.T) {
	asCVE := Finding{Ecosystem: "npm", Package: "devalue", Installed: "5.8.0",
		ID: "CVE-2026-123565", Aliases: []string{"GHSA-mcm9-63f2-9j32"}}
	asGHSA := Finding{Ecosystem: "npm", Package: "devalue", Installed: "5.8.0",
		ID: "GHSA-mcm9-63f2-9j32", Aliases: []string{"CVE-2026-123565"}}

	if asCVE.Key() != asGHSA.Key() {
		t.Fatalf("keys differ: %q vs %q — a flip would read as one resolved and one new",
			asCVE.Key(), asGHSA.Key())
	}
}

func TestKeyWithoutAliasesIsTheID(t *testing.T) {
	f := Finding{Ecosystem: "Go", Package: "stdlib", Installed: "1.26", ID: "CVE-2026-39821"}

	if got, want := f.Key(), "Go|stdlib|1.26|CVE-2026-39821"; got != want {
		t.Fatalf("key = %q, want %q — keys already on disk would stop matching", got, want)
	}
}

func TestKeyKeepsDifferentFlawsApart(t *testing.T) {
	a := Finding{Ecosystem: "npm", Package: "devalue", Installed: "5.8.0", ID: "CVE-2026-1"}
	b := Finding{Ecosystem: "npm", Package: "devalue", Installed: "5.8.0", ID: "CVE-2026-2"}

	if a.Key() == b.Key() {
		t.Fatalf("two flaws share the key %q", a.Key())
	}
}
