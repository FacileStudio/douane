package osv

import "testing"

// A CVE twin is usually never fetched, because a closure that rates itself
// needs no second record. It must still win: it resolves at nvd.nist.gov
// whether or not OSV carries it, and demanding a held record here would demote
// almost every npm finding from its CVE to its GHSA.
func TestCanonicalPrefersAnUnfetchedCVE(t *testing.T) {
	ghsa := Vuln{ID: "GHSA-jf85-cpcp-j695", Aliases: []string{"CVE-2019-10744"}}
	id, aliases := Canonical(ghsa, nil)
	if id != "CVE-2019-10744" {
		t.Fatalf("canonical = %q, want CVE-2019-10744", id)
	}
	if len(aliases) != 1 || aliases[0] != "GHSA-jf85-cpcp-j695" {
		t.Fatalf("aliases = %v, want [GHSA-jf85-cpcp-j695]", aliases)
	}
}

// The live shape this exists for: a package query returns GO-2026-5841, whose
// only alias is GHSA-259r-337f-4rfw, and that id 404s on OSV and on
// github.com/advisories alike. Promoting it printed a finding under a key
// nothing anywhere can be asked about.
func TestCanonicalRefusesAnIDProvenAbsent(t *testing.T) {
	v := Vuln{ID: "GO-2026-5841", Aliases: []string{"GHSA-259r-337f-4rfw"}}
	id, aliases := Canonical(v, map[string]bool{"GHSA-259r-337f-4rfw": true})
	if id != "GO-2026-5841" {
		t.Fatalf("canonical = %q, want GO-2026-5841, OSV has no record for the GHSA", id)
	}
	if len(aliases) != 1 || aliases[0] != "GHSA-259r-337f-4rfw" {
		t.Fatalf("aliases = %v, want the unheld id kept as an alias, printed and searchable", aliases)
	}
}

func TestCanonicalFallsBackToOwnID(t *testing.T) {
	v := Vuln{ID: "GO-2021-0053"}
	if id, _ := Canonical(v, nil); id != "GO-2021-0053" {
		t.Fatalf("canonical = %q, want GO-2021-0053", id)
	}
}
