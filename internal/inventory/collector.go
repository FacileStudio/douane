package inventory

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/FacileStudio/douane/internal/finding"
)

const binaryBunLock = "bun.lockb"

const binaryBunLockDetail = "binary bun lockfile is unreadable, run `bun install --save-text-lockfile` to emit bun.lock"

type collector struct {
	root   string
	seen   map[string]bool
	noted  map[string]bool
	parsed map[string]bool
	pkgs   []finding.Package
	gaps   []finding.Gap
}

// visit records a per-file failure and keeps walking. Only the root itself is
// fatal: a target that cannot be read at all is bad input, where a directory
// deeper in the tree is one unanswered question in an otherwise usable scan.
func (c *collector) visit(path string, d fs.DirEntry, err error) error {
	if err != nil {
		if path == c.root {
			return err
		}
		c.gap(finding.GapUnreadable, rel(c.root, path), err.Error())
		return nil
	}
	if d.IsDir() {
		if path != c.root && skipDirs[d.Name()] {
			return filepath.SkipDir
		}
		return nil
	}
	c.file(path, d.Name())
	return nil
}

// file dispatches one filename. The binary bun lockfile is silent when the
// text one beside it already parsed: WalkDir is lexical, so bun.lock is always
// visited before bun.lockb, and a repo that migrated correctly but left the
// old file committed has nothing wrong with it.
func (c *collector) file(path, name string) {
	for _, p := range parsers {
		if name == p.file {
			c.collect(p, path)
			return
		}
	}
	if name == binaryBunLock {
		if !c.parsed[filepath.Join(filepath.Dir(path), "bun.lock")] {
			c.gap(finding.GapUnreadable, rel(c.root, path), binaryBunLockDetail)
		}
		return
	}
	if detail, ok := unsupported(path, name); ok {
		c.gap(finding.GapUnsupported, rel(c.root, path), detail)
	}
}

func (c *collector) collect(p parser, path string) {
	source := rel(c.root, path)
	data, err := os.ReadFile(path)
	if err != nil {
		c.gap(finding.GapUnreadable, source, err.Error())
		return
	}
	found, gaps, err := p.parse(path, data)
	for _, g := range gaps {
		c.gap(g.Kind, source, g.Detail)
	}
	if err != nil {
		c.gap(finding.GapUnreadable, source, err.Error())
		return
	}
	c.parsed[path] = true
	for _, pkg := range found {
		c.keep(pkg, source)
	}
}

// keep records one package, or the gap that says why it was dropped. An empty
// name is fatal well beyond its own lockfile: OSV answers a batch holding one
// such query with HTTP 400 and no results at all, so a single bad entry costs
// every other package in the same 500-query request. An empty version is
// merely wrong, and returns every advisory the module has ever had.
func (c *collector) keep(pkg finding.Package, source string) {
	if pkg.Name == "" || pkg.Version == "" {
		c.gap(finding.GapUnreadable, source, dropped(pkg))
		return
	}
	pkg.Source = source
	key := pkg.Ecosystem + "|" + pkg.Name + "|" + pkg.Version
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	c.pkgs = append(c.pkgs, pkg)
}

func dropped(pkg finding.Package) string {
	if pkg.Name == "" {
		return fmt.Sprintf("dropped an entry with no package name at version %q", pkg.Version)
	}
	return "dropped " + pkg.Name + " with no version"
}

func (c *collector) gap(kind finding.GapKind, subject, detail string) {
	key := string(kind) + "|" + subject + "|" + detail
	if c.noted[key] {
		return
	}
	c.noted[key] = true
	c.gaps = append(c.gaps, finding.Gap{Kind: kind, Subject: subject, Detail: detail})
}
