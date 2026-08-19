package inventory

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

// parseGoMod reads the require directives of a go.mod, in both the block and
// the single-line form. Indirect dependencies are included: they ship in the
// binary exactly like direct ones.
func parseGoMod(_ string, data []byte) ([]finding.Package, error) {
	var pkgs []finding.Package
	inBlock := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line, keep := requireLine(strip(sc.Text()), &inBlock)
		if !keep {
			continue
		}
		if pkg, ok := requirement(line); ok {
			pkgs = append(pkgs, pkg)
		}
	}
	return pkgs, sc.Err()
}

func strip(line string) string {
	line = strings.TrimSpace(line)
	if i := strings.Index(line, "//"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	return line
}

func requireLine(line string, inBlock *bool) (string, bool) {
	switch {
	case line == "":
		return "", false
	case line == "require (":
		*inBlock = true
		return "", false
	case *inBlock && line == ")":
		*inBlock = false
		return "", false
	case strings.HasPrefix(line, "require "):
		return strings.TrimPrefix(line, "require "), true
	case *inBlock:
		return line, true
	}
	return "", false
}

func requirement(line string) (finding.Package, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.HasPrefix(fields[1], "v") {
		return finding.Package{}, false
	}
	return finding.Package{
		Name:      fields[0],
		Ecosystem: "Go",
		Version:   trimVPrefix(fields[1]),
	}, true
}
