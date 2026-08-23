package inventory

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

// goVersionPattern accepts the release forms a go.mod carries: "1.25",
// "1.25.0" and the pre-release "1.26rc1". Validation is not politeness. OSV
// answers a version it cannot parse with every advisory it holds for the
// module — 149 for stdlib on 2026-08-23, against 46 for a real 1.25.0 — so an
// unchecked string reads as a repo in ruins rather than as an error.
var goVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?((rc|beta|alpha)[0-9]+)?$`)

// goDirectives holds the two go.mod lines that name a Go release rather than a
// dependency. OSV publishes standard-library and go-command flaws under the
// synthetic module names "stdlib" and "toolchain", queried in ecosystem "Go"
// like any other package, so these lines are where a Go repo's largest source
// of advisories is declared and the only place douane can read it from.
type goDirectives struct {
	lang      string
	toolchain string
}

// read records the go and toolchain directives of one go.mod line.
func (d *goDirectives) read(line string) {
	switch {
	case strings.HasPrefix(line, "go "):
		d.lang = strings.TrimSpace(strings.TrimPrefix(line, "go "))
	case strings.HasPrefix(line, "toolchain "):
		d.toolchain = strings.TrimSpace(strings.TrimPrefix(line, "toolchain "))
	}
}

// packages emits the two synthetic modules for the declared release, or the
// gap that says why it could not. Both carry the same version: one Go release
// ships one standard library and one go command.
func (d goDirectives) packages() ([]finding.Package, []finding.Gap) {
	v, ok := d.version()
	if !ok {
		return nil, []finding.Gap{{Kind: finding.GapUnreadable, Detail: d.detail()}}
	}
	return []finding.Package{
		{Name: "stdlib", Ecosystem: "Go", Version: v},
		{Name: "toolchain", Ecosystem: "Go", Version: v},
	}, nil
}

// version resolves the release the module is built with. A toolchain line wins
// over the go line because it names the release itself, where the go line only
// sets the language floor; "toolchain default" and any other unparseable value
// falls back to the go line, which is what the go command does with it.
func (d goDirectives) version() (string, bool) {
	if v, ok := goVersion(d.toolchain); ok {
		return v, true
	}
	return goVersion(d.lang)
}

// detail explains which of the two ways of having no usable release happened,
// since a missing directive and a malformed one are fixed differently.
func (d goDirectives) detail() string {
	raw := strings.TrimSpace(d.lang + " " + d.toolchain)
	if raw == "" {
		return "no go directive, so the standard library and toolchain were not queried"
	}
	return fmt.Sprintf("unrecognised Go release %q, so the standard library and toolchain were not queried", raw)
}

// goVersion strips the "go" a toolchain line prefixes its release with and
// reports whether what remains is a release OSV can compare. A two-component
// "1.25" is left alone: OSV answers it exactly as it answers "1.25.0", same 46
// stdlib advisories, so padding it would only invent a version nobody wrote.
func goVersion(s string) (string, bool) {
	v := strings.TrimPrefix(s, "go")
	return v, goVersionPattern.MatchString(v)
}
