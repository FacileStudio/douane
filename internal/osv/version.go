package osv

import (
	"cmp"
	"strconv"
	"strings"
)

// compareVersions orders two versions the way semver does: the dotted core
// numerically, then the pre-release tail. Build metadata is ignored, because
// semver says it carries no ordering — "1.0.0+meta" is the same release as
// "1.0.0", not a pre-release of it.
func compareVersions(a, b string) int {
	aCore, aPre := splitVersion(a)
	bCore, bPre := splitVersion(b)
	if c := compareCore(aCore, bCore); c != 0 {
		return c
	}
	return comparePrerelease(aPre, bPre)
}

// splitVersion drops the "v" prefix and the "+build" metadata and returns the
// core version and the pre-release tail. Metadata goes first so that
// "1.0.0-rc.1+meta" keeps "rc.1" and not "rc.1+meta".
func splitVersion(v string) (string, string) {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

func compareCore(a, b string) int {
	aParts, bParts := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(aParts) || i < len(bParts); i++ {
		if c := compareIdent(segment(aParts, i), segment(bParts, i)); c != 0 {
			return c
		}
	}
	return 0
}

func segment(parts []string, i int) string {
	if i < len(parts) {
		return parts[i]
	}
	return "0"
}

// comparePrerelease orders pre-release tails per semver 11.4: identifier by
// identifier, and a shorter tail below a longer one that shares its prefix. A
// version with no tail is the release itself and outranks every pre-release of
// it, which is the rule Go advisories lean on when they open a major branch
// with "1.24.0-0".
func comparePrerelease(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "":
		return 1
	case b == "":
		return -1
	}
	aIDs, bIDs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(aIDs) && i < len(bIDs); i++ {
		if c := compareIdent(aIDs[i], bIDs[i]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(aIDs), len(bIDs))
}

// compareIdent orders two identifiers numerically when both are numbers, so
// that "rc.2" sorts below "rc.10" rather than above it the way a string
// comparison would have it. A number sorts below any word, per semver 11.4.
func compareIdent(a, b string) int {
	ai, aerr := strconv.Atoi(a)
	bi, berr := strconv.Atoi(b)
	switch {
	case aerr == nil && berr == nil:
		return cmp.Compare(ai, bi)
	case aerr == nil:
		return -1
	case berr == nil:
		return 1
	}
	return strings.Compare(a, b)
}
