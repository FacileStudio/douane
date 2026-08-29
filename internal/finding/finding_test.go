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
