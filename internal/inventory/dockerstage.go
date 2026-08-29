package inventory

import (
	"bufio"
	"bytes"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// dockerStage is one FROM block of a Dockerfile: whether its base image is a
// golang one, the Go release line that image ships, whether the block runs the
// go command at all, and the go.mod paths it copies out of the build context.
type dockerStage struct {
	golang  bool
	release string
	builds  bool
	mods    []string
}

// isDockerfile reports whether a filename names a Dockerfile. Both suffix
// conventions are accepted because both are in use, and a repo that keeps a
// second image for development builds it with its own base tag.
func isDockerfile(name string) bool {
	return name == "Dockerfile" ||
		strings.HasPrefix(name, "Dockerfile.") ||
		strings.HasSuffix(name, ".Dockerfile")
}

// dockerLogicalLines splits a Dockerfile into instructions, joining the lines
// a trailing backslash continues and dropping comments. An instruction split
// across three physical lines is one instruction, and reading it as three
// hides whichever part carried the go.mod.
func dockerLogicalLines(data []byte) []string {
	var out []string
	var buf strings.Builder
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			buf.WriteString(strings.TrimSpace(strings.TrimSuffix(line, "\\")) + " ")
			continue
		}
		buf.WriteString(line)
		if joined := strings.TrimSpace(buf.String()); joined != "" {
			out = append(out, joined)
		}
		buf.Reset()
	}
	return out
}

// golangRelease reads the arguments of a FROM instruction and reports the Go
// release line its base image ships. The second result says the image is a
// golang one at all, so that a Go builder whose tag names no release can be
// told apart from a base image douane has no opinion about.
//
// An empty release with a true second result is "golang, but the tag names no
// version": :latest, :alpine, or no tag. None of those may be turned into a
// version, since inventing one is exactly the error this file exists to fix.
func golangRelease(args string) (string, bool) {
	fields := strings.Fields(args)
	if len(fields) == 0 {
		return "", false
	}
	image, _, _ := strings.Cut(fields[0], "@")
	repo, tag := image, ""
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		repo, tag = image[:i], image[i+1:]
	}
	if path.Base(repo) != "golang" {
		return "", false
	}
	release, _, _ := strings.Cut(tag, "-")
	if v, ok := goVersion(release); ok {
		return v, true
	}
	return "", true
}

// copyModules names the go.mod files a COPY instruction brings into a stage.
// The last field is the destination and the flags are not paths, so only the
// sources between them can name one. A --from source is copied out of an
// earlier stage rather than out of the repo, so it names no file on disk.
func copyModules(args string) []string {
	fields := strings.Fields(args)
	var out []string
	for i, f := range fields {
		switch {
		case strings.HasPrefix(f, "--from"):
			return nil
		case strings.HasPrefix(f, "--"), i == len(fields)-1:
			continue
		case path.Base(f) == "go.mod":
			out = append(out, f)
		}
	}
	return out
}

// runsGo reports whether a RUN instruction drives the go command. It is what
// separates a stage that builds a module it never named from a stage that
// merely happens to sit on a golang image, and only the first is worth a gap.
func runsGo(args string) bool {
	for _, cmd := range []string{"go build", "go install", "go mod download", "go run"} {
		if strings.Contains(args, cmd) {
			return true
		}
	}
	return false
}

// modulePath resolves a COPY source to the go.mod it names, keyed the way
// inventory.Scan keys a package source: relative to root. COPY paths are
// relative to the build context, which for every image in this suite is the
// repo root, so that is tried first and the Dockerfile's own directory second.
// A source that resolves to no file on disk names a context douane is not
// looking at, and is dropped rather than recorded against a module that may
// not exist.
func modulePath(root, dir, src string) (string, bool) {
	for _, base := range []string{root, dir} {
		p := filepath.Join(base, filepath.FromSlash(src))
		if _, err := os.Stat(p); err == nil {
			return rel(root, p), true
		}
	}
	return "", false
}
