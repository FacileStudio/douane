package inventory

import (
	"path/filepath"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "target": true,
	"dist": true, "build": true, ".svelte-kit": true, ".venv": true,
}

type parser struct {
	file  string
	parse func(path string, data []byte) ([]finding.Package, []finding.Gap, error)
}

var parsers = []parser{
	{"go.mod", parseGoMod},
	{"package-lock.json", parseNPMLock},
	{"bun.lock", parseBunLock},
	{"Cargo.lock", parseCargoLock},
}

// Lockfiles lists the lockfile names douane recognises, so a caller can tell
// a project directory from any other directory without duplicating the list.
// The ecosystems douane cannot read are in it too: a pnpm checkout is still a
// project, and one it never opens is one it can never report a gap for.
func Lockfiles() []string {
	out := make([]string, 0, len(parsers)+len(unsupportedFiles))
	for _, p := range parsers {
		out = append(out, p.file)
	}
	for _, u := range unsupportedFiles {
		out = append(out, u.name)
	}
	return out
}

// Scan walks root and returns every dependency declared by a lockfile it
// recognises, plus a gap for each one it could not read. Directories holding
// installed artefacts rather than sources are skipped, so a vendored copy is
// never mistaken for a declared dependency.
//
// A file that fails to parse costs its own packages and nothing else. Failing
// the walk instead discarded every package already collected, so one stale
// fixture under testdata/ used to cost a repo its entire scan.
func Scan(root string) ([]finding.Package, []finding.Gap, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, nil, err
	}
	c := &collector{
		root:   abs,
		seen:   map[string]bool{},
		noted:  map[string]bool{},
		parsed: map[string]bool{},
	}
	if err := filepath.WalkDir(abs, c.visit); err != nil {
		return nil, nil, err
	}
	return c.pkgs, c.gaps, nil
}

func rel(root, path string) string {
	r, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return r
}

func trimVPrefix(v string) string {
	return strings.TrimPrefix(v, "v")
}
