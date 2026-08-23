package inventory

import (
	"strings"
	"testing"
)

func TestStripJSONCKeepsBase64SlashesInStrings(t *testing.T) {
	src := []byte(`{"h":"sha512-a//bc+d","x":1,}`)
	got := string(stripJSONC(src))
	want := `{"h":"sha512-a//bc+d","x":1}`
	if got != want {
		t.Fatalf("stripJSONC = %s, want %s", got, want)
	}
}

func TestStripJSONCRemovesComments(t *testing.T) {
	src := []byte("{\n // a comment\n \"x\": 1, /* block */\n}")
	if got := string(stripJSONC(src)); got != "{\n \n \"x\": 1, \n}" && !validJSONish(got) {
		t.Fatalf("stripJSONC left invalid output: %q", got)
	}
}

func validJSONish(s string) bool {
	return !contains(s, "//") && !contains(s, "/*")
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestSplitNameVersionKeepsScope(t *testing.T) {
	name, version := splitNameVersion("@adobe/css-tools@4.4.4")
	if name != "@adobe/css-tools" || version != "4.4.4" {
		t.Fatalf("splitNameVersion = %q, %q", name, version)
	}
}

func TestParseGoModIncludesIndirect(t *testing.T) {
	src := []byte(strings.Join([]string{
		"module x", "", "go 1.25", "",
		"require (", "\tgithub.com/a/b v1.2.3", "\tgithub.com/c/d v0.4.0 // indirect", ")", "",
		"require github.com/e/f v2.0.0", "",
	}, "\n"))
	pkgs, err := invGoMod(t, src)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(invRequires(pkgs)); n != 3 {
		t.Fatalf("got %d required packages, want 3: %+v", n, pkgs)
	}
	if pkgs[0].Version != "1.2.3" {
		t.Fatalf("version = %q, want 1.2.3 (the v prefix must be stripped for OSV)", pkgs[0].Version)
	}
}

const cargoLock = `[[package]]
name = "mycrate"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
`

func TestParseCargoLockSkipsWorkspaceMembers(t *testing.T) {
	pkgs, _, err := parseCargoLock("Cargo.lock", []byte(cargoLock))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "serde" {
		t.Fatalf("got %+v, want only serde", pkgs)
	}
}
