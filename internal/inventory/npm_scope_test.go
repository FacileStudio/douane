package inventory

import (
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
)

func TestParseNpmScopeDevFlag(t *testing.T) {
	src := `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/serve": { "version": "1.0.0", "dev": true },
    "node_modules/express": { "version": "2.0.0" }
  }
}`
	pkgs, _, err := parseNPMLock("package-lock.json", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if got := pkgByName(t, pkgs, "serve").Scope; got != finding.ScopeDev {
		t.Fatalf("serve scope = %q, want dev", got)
	}
	if got := pkgByName(t, pkgs, "express").Scope; got != finding.ScopeProd {
		t.Fatalf("express scope = %q, want prod", got)
	}
}

func TestParseNpmScopeV1IsProd(t *testing.T) {
	src := `{
  "name": "app",
  "lockfileVersion": 1,
  "dependencies": {
    "leftpad": { "version": "1.0.0" }
  }
}`
	pkgs, _, err := parseNPMLock("package-lock.json", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if got := pkgByName(t, pkgs, "leftpad").Scope; got != finding.ScopeProd {
		t.Fatalf("leftpad scope = %q, want prod", got)
	}
}
