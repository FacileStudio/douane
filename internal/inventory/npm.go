package inventory

import (
	"encoding/json"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

type npmLock struct {
	Packages map[string]struct {
		Version string `json:"version"`
		Link    bool   `json:"link"`
	} `json:"packages"`
	Dependencies map[string]struct {
		Version string `json:"version"`
	} `json:"dependencies"`
}

// parseNPMLock reads a package-lock.json in either the v1 shape (dependencies)
// or the v2/v3 shape (packages keyed by install path).
func parseNPMLock(_ string, data []byte) ([]finding.Package, []finding.Gap, error) {
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, nil, err
	}
	if pkgs := fromPackages(lock); len(pkgs) > 0 {
		return pkgs, nil, nil
	}
	return fromDependencies(lock), nil, nil
}

func fromPackages(lock npmLock) []finding.Package {
	var pkgs []finding.Package
	for path, entry := range lock.Packages {
		name, ok := packageName(path)
		if !ok || entry.Link || entry.Version == "" {
			continue
		}
		pkgs = append(pkgs, finding.Package{Name: name, Ecosystem: "npm", Version: entry.Version})
	}
	return pkgs
}

// packageName reads the dependency name out of an install path. A key ending
// exactly in "node_modules/" yields an empty name, which the collector drops
// with a gap rather than a parser dropping it in silence: OSV refuses a whole
// batch that carries one empty name, not just the query that holds it.
func packageName(path string) (string, bool) {
	idx := strings.LastIndex(path, "node_modules/")
	if path == "" || idx < 0 {
		return "", false
	}
	return path[idx+len("node_modules/"):], true
}

func fromDependencies(lock npmLock) []finding.Package {
	var pkgs []finding.Package
	for name, entry := range lock.Dependencies {
		if entry.Version == "" {
			continue
		}
		pkgs = append(pkgs, finding.Package{Name: name, Ecosystem: "npm", Version: entry.Version})
	}
	return pkgs
}
