package finding

// mergeLines folds groups that differ only by patch level into one action.
// Linearly versioned packages break the one-group-per-decision premise: the Go
// stdlib pseudo-package alone produced six groups at 1.25.8 through 1.25.13,
// when bumping to 1.25.13 clears all six. Merging within a release line makes
// the reported fix count the number of decisions someone actually has to make.
//
// The line is the boundary, not conservatism. A repo with modules on go 1.24
// and go 1.25 yields targets on both lines at once, and collapsing 1.24.x into
// 1.25.x would sell a minor upgrade as a patch bump.
func mergeLines(gs []Group) []Group {
	at := map[string]int{}
	out := make([]Group, 0, len(gs))
	for _, g := range gs {
		k, ok := lineKey(g)
		if !ok {
			out = append(out, g)
			continue
		}
		if i, seen := at[k]; seen {
			out[i] = mergeInto(out[i], g)
			continue
		}
		at[k] = len(out)
		out = append(out, g)
	}
	return out
}

// lineKey names the release line a group's fix lands on. An empty FixedIn has
// no line and never merges: "no fix exists" is a decision of its own, and
// folding it into an upgrade would claim a fix that does not exist.
func lineKey(g Group) (string, bool) {
	if g.FixedIn == "" {
		return "", false
	}
	key := g.Ecosystem + "|" + g.Package + "|" + majorMinor(g.FixedIn)
	if g.Rebuild {
		key += "|rebuild"
	}
	return key, true
}

// SameLine reports whether two versions sit on one release line, which is what
// makes a fix reachable by rebuilding rather than by editing a version. It is
// exported for the caller that knows where build versions come from, because
// this package deliberately does not.
func SameLine(a, b string) bool {
	return a != "" && b != "" && majorMinor(a) == majorMinor(b)
}

// majorMinor returns the first two dot-separated fields of a version, which is
// the release line a patch series belongs to. Shorter versions are their own
// line rather than being padded into somebody else's.
func majorMinor(v string) string {
	dots := 0
	for i := 0; i < len(v); i++ {
		if v[i] != '.' {
			continue
		}
		dots++
		if dots == 2 {
			return v[:i]
		}
	}
	return v
}

// mergeInto folds src into dst on the same release line, keeping the highest
// patch as the target: the newest fix on a line subsumes the older ones, so it
// is the single version that clears every member.
func mergeInto(dst, src Group) Group {
	if lessVersion(dst.FixedIn, src.FixedIn) {
		dst.FixedIn = src.FixedIn
	}
	dst.Count += src.Count
	dst.New += src.New
	dst.KEV = dst.KEV || src.KEV
	dst.IDs = mergeUnique(dst.IDs, src.IDs)
	dst.Targets = mergeUnique(dst.Targets, src.Targets)
	dst.Installed = mergeUnique(dst.Installed, src.Installed)
	if Less(src.worst, dst.worst) {
		dst.worst = src.worst
		dst.Worst = src.worst.Severity
	}
	return dst.finalized()
}

func mergeUnique(dst, src []string) []string {
	for _, s := range src {
		dst = appendUnique(dst, s)
	}
	return dst
}
