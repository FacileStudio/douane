package osv

import "testing"

func TestInformationalReadsAcrossAffectedEntries(t *testing.T) {
	v := Vuln{
		ID: "RUSTSEC-2025-0010",
		Affected: []Affected{
			{Package: PackageRef{Name: "ring", Ecosystem: "crates.io"},
				DatabaseSpecific: AffectedDatabaseSpecific{Informational: "unmaintained"}},
			{Package: PackageRef{Name: "ring", Ecosystem: "crates.io"}, Ranges: nil},
			{Package: PackageRef{Name: "ring", Ecosystem: "crates.io"},
				DatabaseSpecific: AffectedDatabaseSpecific{Informational: "unsound"}},
		},
	}
	if got := Informational(v); got != "unmaintained,unsound" {
		t.Fatalf("Informational = %q, want unmaintained,unsound — distinct categories survive the join", got)
	}
	if !IsInformational(v) {
		t.Fatal("IsInformational = false, want true")
	}
}

func TestInformationalEmptyWhenNoMarker(t *testing.T) {
	v := Vuln{
		ID:       "GHSA-259r-337f-4rfw",
		Affected: []Affected{{Package: PackageRef{Name: "x", Ecosystem: "npm"}}},
	}
	if got := Informational(v); got != "" {
		t.Fatalf("Informational = %q, want empty — a real vulnerability has no category", got)
	}
	if IsInformational(v) {
		t.Fatal("IsInformational = true, want false")
	}
}

func TestInformationalEmptyForEmptyAffected(t *testing.T) {
	if IsInformational(Vuln{ID: "RUSTSEC-2021-0125"}) {
		t.Fatal("IsInformational = true on an advisory with no affected entries")
	}
}
