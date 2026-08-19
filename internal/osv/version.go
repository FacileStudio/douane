package osv

import (
	"strconv"
	"strings"
)

// compareVersions orders two dotted versions numerically, segment by segment,
// falling back to a string comparison for non-numeric segments. A version
// carrying a pre-release suffix sorts below the same version without one.
func compareVersions(a, b string) int {
	aCore, aPre := splitPrerelease(a)
	bCore, bPre := splitPrerelease(b)

	aParts := strings.Split(aCore, ".")
	bParts := strings.Split(bCore, ".")
	for i := 0; i < len(aParts) || i < len(bParts); i++ {
		if c := compareSegment(segment(aParts, i), segment(bParts, i)); c != 0 {
			return c
		}
	}
	switch {
	case aPre == bPre:
		return 0
	case aPre == "":
		return 1
	case bPre == "":
		return -1
	case aPre < bPre:
		return -1
	}
	return 1
}

func splitPrerelease(v string) (string, string) {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

func segment(parts []string, i int) string {
	if i < len(parts) {
		return parts[i]
	}
	return "0"
}

func compareSegment(a, b string) int {
	ai, aerr := strconv.Atoi(a)
	bi, berr := strconv.Atoi(b)
	if aerr == nil && berr == nil {
		switch {
		case ai < bi:
			return -1
		case ai > bi:
			return 1
		}
		return 0
	}
	return strings.Compare(a, b)
}
