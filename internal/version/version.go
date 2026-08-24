// Package version reports the build's own version. Release builds get the tag
// via -ldflags; everything else falls back to the stamp the toolchain records,
// because a literal in the source drifts on the first release nobody remembers
// to bump it for.
package version

import "runtime/debug"

// site is where a rate limiter's operator can find out who is calling.
const site = "https://github.com/FacileStudio/douane"

// unknown is what a build with no stamp at all reports. `go run` and `go test`
// land here: they record no VCS settings and call the main module "(devel)".
const unknown = "dev"

// stamp is injected by release builds (-X .../internal/version.stamp=vX.Y.Z).
// A binary built outside the module proxy records no tag in its build info,
// so without this a goreleaser artifact would report its commit hash where
// every other suite CLI reports its release.
var stamp = ""

// String returns the version of this build: the release stamp when one was
// linked in, else the module's tag, else the commit it came from, marked
// +dirty if the tree had uncommitted changes.
func String() string {
	if stamp != "" {
		return stamp
	}
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
