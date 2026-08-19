package inventory

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

var errBinaryLockfile = errors.New(
	"binary bun lockfile is unreadable — run `bun install --save-text-lockfile` to emit bun.lock",
)

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "target": true,
	"dist": true, "build": true, ".svelte-kit": true, ".venv": true,
}

type parser struct {
	file  string
	parse func(path string, data []byte) ([]finding.Package, error)
}

var parsers = []parser{
	{"go.mod", parseGoMod},
	{"package-lock.json", parseNPMLock},
	{"bun.lock", parseBunLock},
	{"Cargo.lock", parseCargoLock},
}

// Lockfiles lists the lockfile names douane recognises, so a caller can tell
// a project directory from any other directory without duplicating the list.
func Lockfiles() []string {
	out := make([]string, 0, len(parsers))
	for _, p := range parsers {
		out = append(out, p.file)
	}
	return out
}

// Scan walks root and returns every dependency declared by a lockfile it
// recognises. Directories holding installed artefacts rather than sources are
// skipped, so a vendored copy is never mistaken for a declared dependency.
func Scan(root string) ([]finding.Package, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	c := &collector{root: abs, seen: map[string]bool{}}
	if err := filepath.WalkDir(abs, c.visit); err != nil {
		return nil, err
	}
	return c.pkgs, nil
}

type collector struct {
	root string
	seen map[string]bool
	pkgs []finding.Package
}

func (c *collector) visit(path string, d fs.DirEntry, err error) error {
	if err != nil {
		return nil
	}
	if d.IsDir() {
		if path != c.root && skipDirs[d.Name()] {
			return filepath.SkipDir
		}
		return nil
	}
	if d.Name() == "bun.lockb" {
		return fmt.Errorf("%s: %w", rel(c.root, path), errBinaryLockfile)
	}
	return c.collectMatching(d.Name(), path)
}

func (c *collector) collectMatching(name, path string) error {
	for _, p := range parsers {
		if name != p.file {
			continue
		}
		if err := c.collect(p, path); err != nil {
			return err
		}
	}
	return nil
}

func (c *collector) collect(p parser, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%s: %w", rel(c.root, path), err)
	}
	found, err := p.parse(path, data)
	if err != nil {
		return fmt.Errorf("%s: %w", rel(c.root, path), err)
	}
	for _, pkg := range found {
		pkg.Source = rel(c.root, path)
		key := pkg.Ecosystem + "|" + pkg.Name + "|" + pkg.Version
		if c.seen[key] {
			continue
		}
		c.seen[key] = true
		c.pkgs = append(c.pkgs, pkg)
	}
	return nil
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
