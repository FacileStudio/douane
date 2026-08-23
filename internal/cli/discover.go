package cli

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/inventory"
	"github.com/FacileStudio/douane/internal/output"
)

// discover lists the projects directly under root. It does not recurse: a
// sweep runs over a directory of checkouts, and walking deeper would rediscover
// every nested app as a repository of its own.
func discover(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		dir := filepath.Join(root, e.Name())
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		if isProject(dir) {
			out = append(out, dir)
		}
	}
	return out, nil
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
func inventories(dirs []string) []*repoScan {
	var out []*repoScan
	for _, dir := range dirs {
		r := &repoScan{report: output.Report{
			Name:   filepath.Base(dir),
			Target: dir,
			New:    map[string]bool{},
		}}
		pkgs, gaps, err := inventory.Scan(dir)
		r.report.Gaps = gaps
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
