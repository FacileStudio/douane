package cli

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/inventory"
	"github.com/FacileStudio/douane/internal/output"
)

// discover lists the projects to sweep. Point it at a directory of checkouts
// and it takes each direct child that is one; point it at a checkout itself
// and it sweeps that, rather than reporting an empty fleet. It does not
// recurse: walking deeper would rediscover every nested app as a repository of
// its own. A testdata child is a fixture, not a repository, unless o asks
// for fixtures.
func discover(root string, o inventory.Options) ([]string, error) {
	if isProject(root) {
		return []string{filepath.Clean(root)}, nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		dir := filepath.Join(root, e.Name())
		if isChildProject(dir, e.Name(), o) {
			out = append(out, dir)
		}
	}
	return out, nil
}

func isChildProject(dir, name string, o inventory.Options) bool {
	if strings.HasPrefix(name, ".") || o.SkipsFixtures(name) {
		return false
	}
	info, err := os.Stat(dir)
	return err == nil && info.IsDir() && isProject(dir)
}

// isProject reports whether dir is worth scanning: a checkout, or anything
// declaring dependencies at its top level.
func isProject(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		return true
	}
	for _, name := range inventory.Lockfiles() {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

// inventories reads each project's lockfiles. Every project discovered stays
// in the report, including the ones that yielded nothing: a repository on an
// ecosystem douane cannot parse used to vanish from the sweep entirely, which
// reads as "clean" and is the one answer douane must never give by omission.
// One unreadable lockfile must not cost the fleet its sweep either, so the
// error becomes that repository's gap, which is rendered in every format, and
// the sweep carries on.
func inventories(dirs []string, o inventory.Options) []*repoScan {
	var out []*repoScan
	for _, dir := range dirs {
		r := &repoScan{report: output.Report{
			Name:   filepath.Base(dir),
			Target: dir,
			New:    map[string]bool{},
		}}
		pkgs, gaps, err := inventory.Scan(dir, o)
		build, buildGaps := inventory.BuildLines(dir, o)
		r.report.BuildLines = build
		r.report.Gaps = append(gaps, buildGaps...)
		if err != nil {
			r.report.Failed = true
			r.report.Gaps = append(r.report.Gaps, finding.Gap{
				Kind:    finding.GapUnreadable,
				Subject: filepath.Base(dir),
				Detail:  err.Error(),
			})
		}
		r.pkgs, r.report.Packages = pkgs, len(pkgs)
		out = append(out, r)
	}
	return out
}
