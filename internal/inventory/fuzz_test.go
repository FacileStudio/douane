package inventory

import (
	"testing"
	"time"

	"github.com/FacileStudio/douane/internal/finding"
)

const (
	fuzzMaxInput = 1 << 20
	fuzzBudget   = 2 * time.Second
)

const fuzzBunLock = `{
  // bun writes JSONC
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "root", "dependencies": { "lib-a": "^1.0.0" }, "devDependencies": { "tool-x": "^1" } },
  },
  "packages": {
    "lib-a": ["lib-a@1.0.0", "", { "dependencies": { "tool-x": "^1" } }, "sha512-a//bc+d=="],
    "tool-x": ["tool-x@1.0.0", "", {}, "hash"], /* trailing */
    "@repo/logger": ["@repo/logger@workspace:packages/logger"],
  },
}`

// fuzzParse runs one lockfile parser under the property every parser owes an
// untrusted file: it returns, and quickly. An empty name or version is not a
// failure here, because the collector turns those into gaps by design.
func fuzzParse(f *testing.F, parse func(string, []byte) ([]finding.Package, []finding.Gap, error), seeds ...string) {
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			t.Skip()
		}
		start := time.Now()
		pkgs, gaps, err := parse("lockfile", data)
		if elapsed := time.Since(start); elapsed > fuzzBudget {
			t.Fatalf("parse took %s on %d bytes: %d packages, %d gaps, err %v",
				elapsed, len(data), len(pkgs), len(gaps), err)
		}
	})
}

func FuzzParseGoMod(f *testing.F) {
	fuzzParse(f, parseGoMod,
		"module x\n\ngo 1.25.0\n\ntoolchain go1.25.7\n",
		"module x\n\ngo 1.25\n\nrequire (\n\tgithub.com/a/b v1.2.3\n\tgithub.com/c/d v0.4.0 // indirect\n)\n\nrequire github.com/e/f v2.0.0\n",
		"module x\n\ngo 1.26rc1\n\ntoolchain default\n")
}

func FuzzParseNPMLock(f *testing.F) {
	fuzzParse(f, parseNPMLock,
		`{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/serve":{"version":"1.0.0","dev":true},"node_modules/a/node_modules/b":{"version":"2.0.0"},"node_modules/":{"version":"1.0.0"},"node_modules/l":{"link":true}}}`,
		`{"lockfileVersion":1,"dependencies":{"express":{"version":"4.18.2"}}}`)
}

func FuzzParseBunLock(f *testing.F) {
	fuzzParse(f, parseBunLock, fuzzBunLock, `{"packages":{"x":[]}}`, "{\"a\":\"\\\"//\"}")
}

func FuzzStripJSONC(f *testing.F) {
	for _, s := range []string{fuzzBunLock, `{"h":"sha512-a//bc+d","x":1,}`, "{\n // c\n \"x\": 1, /* b */\n}", "/*", "//", "\"\\"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			t.Skip()
		}
		if out := stripJSONC(data); len(out) > len(data) {
			t.Fatalf("stripJSONC grew %d bytes into %d", len(data), len(out))
		}
	})
}

func FuzzParseCargoLock(f *testing.F) {
	fuzzParse(f, parseCargoLock, cargoLock, "[[package]]\nname = \"x\"\nsource = \"git\"\n")
}

func FuzzDockerfile(f *testing.F) {
	root := f.TempDir()
	for _, s := range []string{invRegistreDockerfile, invJournalDockerfile, "FROM golang\nRUN go build \\\n", "FROM golang:1.26rc1@sha256:x AS b\nCOPY --chown=1 go.mod ./\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxInput {
			t.Skip()
		}
		b := &buildLines{gapSet: gapSet{noted: map[string]bool{}}, root: root, lines: map[string]string{}}
		start := time.Now()
		b.parse(root+"/Dockerfile", data)
		if elapsed := time.Since(start); elapsed > fuzzBudget {
			t.Fatalf("parse took %s on %d bytes", elapsed, len(data))
		}
	})
}
