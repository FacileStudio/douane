package osv

import (
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
)

func TestCanonicalPrefersCVE(t *testing.T) {
	id, aliases := Canonical(Vuln{ID: "GHSA-jf85-cpcp-j695", Aliases: []string{"CVE-2019-10744"}})
	if id != "CVE-2019-10744" {
		t.Fatalf("canonical = %q, want CVE-2019-10744", id)
	}
	if len(aliases) != 1 || aliases[0] != "GHSA-jf85-cpcp-j695" {
		t.Fatalf("aliases = %v, want [GHSA-jf85-cpcp-j695]", aliases)
	}
}

func TestCanonicalFallsBackToOwnID(t *testing.T) {
	if id, _ := Canonical(Vuln{ID: "GO-2021-0053"}); id != "GO-2021-0053" {
		t.Fatalf("canonical = %q, want GO-2021-0053", id)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.10.0", "1.9.0", 1},
		{"2.5.6", "4.0.5", -1},
		{"8.21.0", "8.20.1", 1},
		{"1.0.0", "1.0", 0},
		{"1.0.0-rc1", "1.0.0", -1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestFixedInPicksTheInstalledBranch(t *testing.T) {
	events := []Event{{Fixed: "2.5.6"}, {Fixed: "4.0.6"}}
	ranges := []Range{{Type: "SEMVER", Events: events}}
	affected := Affected{Package: PackageRef{Name: "form-data", Ecosystem: "npm"}, Ranges: ranges}
	v := Vuln{Affected: []Affected{affected}}
	if got := FixedIn(v, finding.Package{Name: "form-data", Version: "4.0.5"}); got != "4.0.6" {
		t.Fatalf("FixedIn = %q, want 4.0.6 (2.5.6 is a lower branch, not a fix)", got)
	}
	if got := FixedIn(v, finding.Package{Name: "form-data", Version: "9.0.0"}); got != "" {
		t.Fatalf("FixedIn = %q, want empty when no fix exists above the installed version", got)
	}
}
