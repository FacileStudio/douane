// Package version reports the build's own version. It reads the stamp the
// toolchain records rather than a literal in the source, because a literal
// drifts on the first release nobody remembers to bump it for.
package version

import "runtime/debug"

// site is where a rate limiter's operator can find out who is calling.
const site = "https://github.com/FacileStudio/douane"

// unknown is what a build with no stamp at all reports. `go run` and `go test`
// land here: they record no VCS settings and call the main module "(devel)".
const unknown = "dev"

// String returns the version of this build: the module's tag when it was built
// from one, otherwise the commit it came from, marked +dirty if the tree had
// uncommitted changes.
func String() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return unknown
	}
	return fromBuildInfo(bi)
}

// UserAgent is the identity every douane HTTP client must send. Go's default
// Go-http-client/1.1 is what rate limiters block first, and an operator who
// wants to complain about our traffic needs somewhere to complain to.
func UserAgent() string {
	return "douane/" + String() + " (+" + site + ")"
}

func fromBuildInfo(bi *debug.BuildInfo) string {
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var rev, dirty string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value[:min(12, len(s.Value))]
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "+dirty"
			}
		}
	}
	if rev == "" {
		return unknown
	}
	return rev + dirty
}
