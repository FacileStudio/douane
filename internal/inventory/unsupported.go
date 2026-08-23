package inventory

import (
	"os"
	"path/filepath"
	"strings"
)

// unsupportedFile names a lockfile douane recognises but cannot read, and the
// ecosystem it belongs to. Detecting one is not the same as parsing it: a repo
// whose only lockfile is a pnpm one reports no packages at all, and a scan
// that reports nothing is indistinguishable from a scan that found nothing.
type unsupportedFile struct{ name, ecosystem string }

// unsupportedFiles is ordered rather than a map so that Lockfiles returns the
// same list every call.
var unsupportedFiles = []unsupportedFile{
	{"pnpm-lock.yaml", "pnpm"},
	{"yarn.lock", "yarn"},
	{"requirements.txt", "pip"},
	{"poetry.lock", "poetry"},
	{"Pipfile.lock", "pipenv"},
	{"uv.lock", "uv"},
	{"Gemfile.lock", "bundler"},
	{"composer.lock", "composer"},
	{"packages.lock.json", "NuGet"},
	{"pubspec.lock", "pub"},
	{"go.sum", "Go"},
}

// unsupported reports the gap detail for a file douane cannot read, if this is
// one. A go.sum only counts without a go.mod beside it, since the go.mod is
// the file douane actually reads, and a .csproj is the only NuGet manifest
// many projects carry.
func unsupported(path, name string) (string, bool) {
	if name == "go.sum" {
		if _, err := os.Stat(filepath.Join(filepath.Dir(path), "go.mod")); err == nil {
			return "", false
		}
		return unsupportedDetail("Go"), true
	}
	if strings.HasSuffix(name, ".csproj") {
		return unsupportedDetail("NuGet"), true
	}
	for _, u := range unsupportedFiles {
		if name == u.name {
			return unsupportedDetail(u.ecosystem), true
		}
	}
	return "", false
}

func unsupportedDetail(ecosystem string) string {
	return ecosystem + " dependencies, an ecosystem douane cannot read"
}
