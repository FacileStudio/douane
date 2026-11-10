package finding

import "testing"

func flaw(id string, aliases ...string) Finding {
	return Finding{Ecosystem: "Go", Package: "stdlib", Installed: "1.22", ID: id, Aliases: aliases}
}

func TestALowRankedAliasDoesNotMoveACVEKey(t *testing.T) {
	before := flaw("CVE-2023-45288", "GO-2024-2687")
	after := flaw("CVE-2023-45288", "GO-2024-2687", "BIT-golang-2023-45288")

	if before.Key() != after.Key() || after.KeyName() != "CVE-2023-45288" {
		t.Fatalf("key moved from %q to %q when a BIT- alias appeared", before.Key(), after.Key())
	}
}

func TestAnAssignedCVEMovesTheKeyOnce(t *testing.T) {
	ghsaOnly := flaw("GHSA-aaaa-bbbb-cccc")
	withCVE := flaw("GHSA-aaaa-bbbb-cccc", "CVE-2026-1")
	later := flaw("GHSA-aaaa-bbbb-cccc", "CVE-2026-1", "BIT-x-2026-1", "GO-2026-9")

	if ghsaOnly.KeyName() != "GHSA-aaaa-bbbb-cccc" || withCVE.KeyName() != "CVE-2026-1" {
		t.Fatalf("names = %q then %q", ghsaOnly.KeyName(), withCVE.KeyName())
	}
	if later.Key() != withCVE.Key() {
		t.Fatalf("the key moved again after the CVE: %q vs %q", withCVE.Key(), later.Key())
	}
}

func TestTiesWithinARankAreStable(t *testing.T) {
	a := flaw("GHSA-zzzz-0000-0000", "GHSA-aaaa-0000-0000")
	b := flaw("GHSA-aaaa-0000-0000", "GHSA-zzzz-0000-0000")

	if a.Key() != b.Key() || a.KeyName() != "GHSA-aaaa-0000-0000" {
		t.Fatalf("keys %q and %q, want both on the smallest GHSA", a.Key(), b.Key())
	}
}

func TestNativeIDsOutrankUnknownPrefixes(t *testing.T) {
	if got := flaw("BIT-golang-1", "GO-2026-1").KeyName(); got != "GO-2026-1" {
		t.Fatalf("name = %q, want the GO- primary over a BIT- copy", got)
	}
}

func TestBlankAliasesAreIgnored(t *testing.T) {
	if got := flaw("GO-2026-1", "", "  ").Names(); len(got) != 1 {
		t.Fatalf("names = %q, want only the id", got)
	}
}
