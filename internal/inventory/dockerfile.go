package inventory

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

const unnamedModuleDetail = "a golang build stage runs the go command but copies no go.mod, " +
	"so the module it builds cannot be named"

const untaggedImageDetail = "a golang build stage carries no Go release in its image tag, " +
	"so the release it builds with cannot be read"

// buildLines accumulates the answer of one walk: the release line per module,
// and the gaps for the stages that could not be resolved to either.
type buildLines struct {
	gapSet
	root  string
	lines map[string]string
}

// BuildLines maps a module's go.mod path, relative to root, to the Go release
// line the Dockerfile builds it with.
//
// Since Go 1.21 the go directive is a minimum, not the release the binary
// ships: the toolchain that compiles it is whichever one is installed, if that
// is newer. Every containerised app here builds from a floating tag such as
// golang:1.25-alpine, which resolves at build time to the newest 1.25.x, so
// the version read out of a go.mod is routinely older than the standard
// library actually in production. Measured across the fleet, 965 of some 1900
// standard-library findings are already fixed in the deployed image.
//
// Only the modules a golang stage copies a go.mod for are mapped, never every
// module in the repo. A library distributed as source, such as a repo's own
// SDK, is compiled by its consumers, so its go directive genuinely is the
// release it is built with and no image tag may overrule it.
func BuildLines(root string) (map[string]string, []finding.Gap) {
	b := &buildLines{
		gapSet: gapSet{noted: map[string]bool{}},
		lines:  map[string]string{},
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		b.gap(finding.GapUnreadable, root, err.Error())
		return b.lines, b.gaps
	}
	b.root = abs
	if err := filepath.WalkDir(abs, b.visit); err != nil {
		b.gap(finding.GapUnreadable, root, err.Error())
	}
	return b.lines, b.gaps
}

// visit records a per-file failure and keeps walking, like the lockfile walk
// beside it. Only the root itself is fatal: a directory deeper in the tree is
// one unanswered question in an otherwise usable answer.
func (b *buildLines) visit(path string, d fs.DirEntry, err error) error {
	if err != nil {
		if path == b.root {
			return err
		}
		b.gap(finding.GapUnreadable, rel(b.root, path), err.Error())
		return nil
	}
	if d.IsDir() {
		if path != b.root && skipDirs[d.Name()] {
			return filepath.SkipDir
		}
		return nil
	}
	if isDockerfile(d.Name()) {
		b.file(path)
	}
	return nil
}

// file reads one Dockerfile, closing each stage as the next FROM opens it and
// once more at the end, since the last stage has no FROM to close it.
func (b *buildLines) file(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		b.gap(finding.GapUnreadable, rel(b.root, path), err.Error())
		return
	}
	var st dockerStage
	for _, line := range dockerLogicalLines(data) {
		verb, args, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "FROM":
			b.stage(path, st)
			st = dockerStage{}
			st.release, st.golang = golangRelease(args)
		case "COPY":
			st.mods = append(st.mods, copyModules(args)...)
		case "RUN":
			st.builds = st.builds || runsGo(args)
		}
	}
	b.stage(path, st)
}

// stage records what one FROM block resolved to. A stage on any other base
// image says nothing, and neither does a golang stage that only carries a
// binary out of an earlier one.
//
// A golang stage that runs the go command but copies no go.mod builds a module
// douane cannot name, and that is reported rather than guessed: applying the
// image tag to every module in the repo would overwrite the release of any
// library the repo also publishes as source.
func (b *buildLines) stage(path string, st dockerStage) {
	if !st.golang {
		return
	}
	source := rel(b.root, path)
	if len(st.mods) == 0 {
		if st.builds {
			b.gap(finding.GapUnresolved, source, unnamedModuleDetail)
		}
		return
	}
	if st.release == "" {
		b.gap(finding.GapUnresolved, source, untaggedImageDetail)
		return
	}
	b.record(filepath.Dir(path), source, st)
}

// record keys each copied go.mod the way inventory.Scan keys a finding target.
// Two stages claiming different release lines for one module keeps the first
// and reports the disagreement, because whichever image is the deployed one,
// douane cannot tell from the source alone and must not present a guess as an
// answer.
func (b *buildLines) record(dir, source string, st dockerStage) {
	for _, src := range st.mods {
		key, ok := modulePath(b.root, dir, src)
		if !ok {
			continue
		}
		if old, seen := b.lines[key]; seen {
			if old != st.release {
				b.gap(finding.GapUnresolved, source, conflictDetail(key, old, st.release))
			}
			continue
		}
		b.lines[key] = st.release
	}
}

func conflictDetail(module, first, second string) string {
	return fmt.Sprintf("%s is built with Go %s by one stage and Go %s by another", module, first, second)
}
