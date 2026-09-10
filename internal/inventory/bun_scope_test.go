package inventory

import (
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
)

// pkgByName finds one emitted package by name in a parser result.
func pkgByName(t *testing.T, pkgs []finding.Package, name string) finding.Package {
	t.Helper()
	for _, p := range pkgs {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("no package %q in %+v", name, pkgs)
	return finding.Package{}
}

func TestParseBunScopeDepAndDevDepIsProd(t *testing.T) {
	src := `{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "root",
      "dependencies": { "lib-a": "^1.0.0" },
      "devDependencies": { "lib-a": "^1.0.0" }
    }
  },
  "packages": {
    "lib-a": ["lib-a@1.0.0", "", {}, "hash"]
  }
}`
	pkgs, _, err := parseBunLock("bun.lock", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if got := pkgByName(t, pkgs, "lib-a").Scope; got != finding.ScopeProd {
		t.Fatalf("lib-a scope = %q, want prod", got)
	}
}

func TestParseBunScopeTransitiveDevOnlyIsDev(t *testing.T) {
	src := `{
  "workspaces": {
    "": { "name": "root", "devDependencies": { "tool-x": "^1.0.0" } }
  },
  "packages": {
    "tool-x": ["tool-x@1.0.0", "", { "dependencies": { "tool-y": "^1.0.0" } }, "hash"],
    "tool-y": ["tool-y@1.0.0", "", {}, "hash"]
  }
}`
	pkgs, _, err := parseBunLock("bun.lock", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if got := pkgByName(t, pkgs, "tool-x").Scope; got != finding.ScopeDev {
		t.Fatalf("tool-x scope = %q, want dev", got)
	}
	if got := pkgByName(t, pkgs, "tool-y").Scope; got != finding.ScopeDev {
		t.Fatalf("tool-y scope = %q, want dev", got)
	}
}

func TestParseBunScopeRootDependencyIsProd(t *testing.T) {
	src := `{
  "workspaces": {
    "": { "name": "root", "dependencies": { "@repo/logger": "workspace:*" } },
    "packages/logger": { "name": "@repo/logger", "dependencies": { "pino": "^9.0.0" } }
  },
  "packages": {
    "@repo/logger": ["@repo/logger@workspace:packages/logger"],
    "pino": ["pino@9.0.0", "", { "dependencies": { "sonic-boom": "^4.0.0" } }, "hash"],
    "sonic-boom": ["sonic-boom@4.0.0", "", {}, "hash"],
    "orphan": ["orphan@1.0.0", "", {}, "hash"]
  }
}`
	pkgs, _, err := parseBunLock("bun.lock", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]finding.Scope{
		"pino":       finding.ScopeProd,
		"sonic-boom": finding.ScopeProd,
		"orphan":     finding.ScopeProd,
	} {
		if got := pkgByName(t, pkgs, name).Scope; got != want {
			t.Fatalf("%s scope = %q, want %q", name, got, want)
		}
	}
}

func TestParseBunScopeNoWorkspacesIsProd(t *testing.T) {
	src := `{
  "lockfileVersion": 1,
  "packages": {
    "lib-a": ["lib-a@1.0.0", "", { "dependencies": { "lib-b": "^1.0.0" } }, "hash"],
    "lib-b": ["lib-b@1.0.0", "", {}, "hash"]
  }
}`
	pkgs, _, err := parseBunLock("bun.lock", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"lib-a", "lib-b"} {
		if got := pkgByName(t, pkgs, name).Scope; got != finding.ScopeProd {
			t.Fatalf("%s scope = %q, want prod", name, got)
		}
	}
}
