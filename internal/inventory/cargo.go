package inventory

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

// parseCargoLock reads the [[package]] stanzas of a Cargo.lock. Entries with no
// source are workspace members rather than registry dependencies.
func parseCargoLock(_ string, data []byte) ([]finding.Package, []finding.Gap, error) {
	var pkgs []finding.Package
	var name, version string
	hasSource := false

	flush := func() {
		if name != "" && version != "" && hasSource {
			pkgs = append(pkgs, finding.Package{Name: name, Ecosystem: "crates.io", Version: version})
		}
		name, version, hasSource = "", "", false
	}

	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "[[package]]":
			flush()
		case strings.HasPrefix(line, "name = "):
			name = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
		case strings.HasPrefix(line, "version = "):
			version = strings.Trim(strings.TrimPrefix(line, "version = "), `"`)
		case strings.HasPrefix(line, "source = "):
			hasSource = true
		}
	}
	flush()
	return pkgs, nil, sc.Err()
}
