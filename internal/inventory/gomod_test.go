package inventory

import (
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
)

func invGoMod(t *testing.T, src []byte) ([]finding.Package, error) {
	t.Helper()
	pkgs, _, err := parseGoMod("go.mod", src)
	return pkgs, err
}

// invRequires drops the synthetic release modules, so a test about require
// lines is not counting the standard library.
func invRequires(pkgs []finding.Package) []finding.Package {
	var out []finding.Package
	for _, p := range pkgs {
		if p.Name != "stdlib" && p.Name != "toolchain" {
			out = append(out, p)
		}
	}
	return out
}

func invRelease(t *testing.T, pkgs []finding.Package, name string) finding.Package {
	t.Helper()
	for _, p := range pkgs {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("no %s package in %+v", name, pkgs)
	return finding.Package{}
}

// TestParseGoModEmitsReleaseModules covers the largest gap douane had. OSV
// carries Go standard-library and go-command advisories under the synthetic
// modules stdlib and toolchain, and the go directive is the only place a
// lockfile scan can learn which release to ask about.
func TestParseGoModEmitsReleaseModules(t *testing.T) {
	pkgs, gaps, err := parseGoMod("go.mod", []byte("module x\n\ngo 1.25.0\n"))
	if err != nil || len(gaps) != 0 {
		t.Fatalf("parseGoMod = %v, %+v", err, gaps)
	}
	for _, name := range []string{"stdlib", "toolchain"} {
		p := invRelease(t, pkgs, name)
		if p.Version != "1.25.0" || p.Ecosystem != "Go" {
			t.Fatalf("%s = %+v, want version 1.25.0 in ecosystem Go", name, p)
		}
	}
}

// TestParseGoModToolchainWins pins the two rules a toolchain line brings: it
// names the release the module is built with, and it spells that release
// "go1.25.7", a form OSV cannot compare. Left unstripped it answers with every
// stdlib advisory it has ever held: 149 against the 29 that are real.
func TestParseGoModToolchainWins(t *testing.T) {
	pkgs, err := invGoMod(t, []byte("module x\n\ngo 1.25.0\n\ntoolchain go1.25.7\n"))
	if err != nil {
		t.Fatal(err)
	}
	if v := invRelease(t, pkgs, "stdlib").Version; v != "1.25.7" {
		t.Fatalf("stdlib version = %q, want 1.25.7", v)
	}
}

// TestParseGoModKeepsTwoComponentRelease: OSV answers "1.25" exactly as it
// answers "1.25.0", same 46 stdlib advisories, so padding it would invent a
// version nobody wrote.
func TestParseGoModKeepsTwoComponentRelease(t *testing.T) {
	pkgs, err := invGoMod(t, []byte("module x\n\ngo 1.25\n"))
	if err != nil {
		t.Fatal(err)
	}
	if v := invRelease(t, pkgs, "stdlib").Version; v != "1.25" {
		t.Fatalf("stdlib version = %q, want 1.25", v)
	}
}

// TestParseGoModUnparseableReleaseIsAGap: OSV answers a version it cannot
// parse with every advisory it holds rather than with an error, so a release
// that does not validate has to be reported as unanswered, never queried.
func TestParseGoModUnparseableReleaseIsAGap(t *testing.T) {
	pkgs, gaps, err := parseGoMod("go.mod", []byte("module x\n\ngo wibble\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(invRequires(pkgs)) != len(pkgs) {
		t.Fatalf("queried a release module for an unparseable directive: %+v", pkgs)
	}
	if len(gaps) != 1 || gaps[0].Kind != finding.GapUnreadable {
		t.Fatalf("gaps = %+v, want one unreadable gap", gaps)
	}
}

func TestParseGoModToolchainDefaultFallsBack(t *testing.T) {
	pkgs, gaps, err := parseGoMod("go.mod", []byte("module x\n\ngo 1.24.0\n\ntoolchain default\n"))
	if err != nil || len(gaps) != 0 {
		t.Fatalf("parseGoMod = %v, %+v", err, gaps)
	}
	if v := invRelease(t, pkgs, "stdlib").Version; v != "1.24.0" {
		t.Fatalf("stdlib version = %q, want 1.24.0", v)
	}
}

func TestParseGoModNoDirectiveIsAGap(t *testing.T) {
	_, gaps, err := parseGoMod("go.mod", []byte("module x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 1 || gaps[0].Kind != finding.GapUnreadable {
		t.Fatalf("gaps = %+v, want one unreadable gap", gaps)
	}
}

func TestGoVersionRejectsWhatOSVCannotCompare(t *testing.T) {
	for _, s := range []string{"", "default", "1", "1.25.0.1", "v1.25.0", "1.25 // x", "wibble"} {
		if v, ok := goVersion(s); ok {
			t.Fatalf("goVersion(%q) = %q, true; want rejected", s, v)
		}
	}
	for _, s := range []string{"1.25", "1.25.0", "1.26rc1", "go1.25.7"} {
		if _, ok := goVersion(s); !ok {
			t.Fatalf("goVersion(%q) rejected a release go.mod can carry", s)
		}
	}
}
