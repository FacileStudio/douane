package inventory

import (
	"encoding/json"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

// splitNameVersion splits a bun descriptor such as "@scope/pkg@1.2.3" on the
// last "@", so scoped package names survive intact.
func splitNameVersion(d string) (string, string) {
	i := strings.LastIndex(d, "@")
	if i <= 0 {
		return d, ""
	}
	return d[:i], d[i+1:]
}

// parseBunLock reads bun's text lockfile. Each package entry is an array whose
// first element is the resolved "name@version" descriptor.
func parseBunLock(_ string, data []byte) ([]finding.Package, error) {
	var lock struct {
		Packages map[string][]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(stripJSONC(data), &lock); err != nil {
		return nil, err
	}
	var pkgs []finding.Package
	for _, entry := range lock.Packages {
		if len(entry) == 0 {
			continue
		}
		var descriptor string
		if err := json.Unmarshal(entry[0], &descriptor); err != nil {
			continue
		}
		name, version := splitNameVersion(descriptor)
		if version == "" || strings.Contains(version, ":") {
			continue
		}
		pkgs = append(pkgs, finding.Package{Name: name, Ecosystem: "npm", Version: version})
	}
	return pkgs, nil
}
