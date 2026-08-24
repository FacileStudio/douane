package finding

import "sort"

// Group is one action that clears findings: take one package to one target
// version, or keep watching a package no fix reaches. It is derived from the
// findings and never replaces them — the flat list stays the source of truth,
// which is what keeps grouping lossless.
type Group struct {
	Ecosystem string   `json:"ecosystem"`
	Package   string   `json:"package"`
	FixedIn   string   `json:"fixed_in,omitempty"`
	Count     int      `json:"count"`
	New       int      `json:"new"`
	KEV       bool     `json:"kev"`
	Worst     Severity `json:"worst_severity"`
	IDs       []string `json:"ids"`
	Targets   []string `json:"targets"`
	Installed []string `json:"installed"`

	worst Finding
}

// WorstFinding returns the most urgent finding in the group under the same
// rank that orders findings. Renderers use it for the summary line and the
// EPSS figure; it is not part of the json shape, where the findings themselves
// carry every field.
func (g Group) WorstFinding() Finding { return g.worst }

// fixKey is the action a finding belongs to: the same package taken to the
// same target version is one decision no matter how many advisories or
// installed versions feed it. An empty FixedIn is its own key per package,
// because "no fix exists" is one decision too — watch this package.
func fixKey(f Finding) string { return f.Ecosystem + "|" + f.Package + "|" + f.FixedIn }

// Groups collapses findings into one Group per (ecosystem, package, target
// version), ordered worst first by the same rank that orders findings. isNew
// reports whether a finding is being seen for the first time; nil treats every
// finding as known.
func Groups(fs []Finding, isNew func(Finding) bool) []Group {
	byKey := map[string]*Group{}
	var keys []string
	for _, f := range fs {
		k := fixKey(f)
		g := byKey[k]
		if g == nil {
			g = &Group{Ecosystem: f.Ecosystem, Package: f.Package, FixedIn: f.FixedIn}
			byKey[k] = g
			keys = append(keys, k)
		}
		g.absorb(f, isNew)
	}
	out := make([]Group, 0, len(byKey))
	for _, k := range keys {
		g := byKey[k]
		sort.Strings(g.IDs)
		sort.Strings(g.Targets)
		sort.Strings(g.Installed)
		out = append(out, *g)
	}
	stable := sort.SliceStable
	stable(out, func(i, j int) bool {
		if Less(out[i].worst, out[j].worst) || Less(out[j].worst, out[i].worst) {
			return Less(out[i].worst, out[j].worst)
		}
		return fixKey(out[i].worst) < fixKey(out[j].worst)
	})
	return out
}

// absorb folds one finding into its group, tracking count, novelty, the KEV
// flag and the worst member under the ordering rank.
func (g *Group) absorb(f Finding, isNew func(Finding) bool) {
	g.Count++
	if isNew != nil && isNew(f) {
		g.New++
	}
	if f.Exploit.KEV {
		g.KEV = true
	}
	if g.Count == 1 || Less(f, g.worst) {
		g.worst = f
		g.Worst = f.Severity
	}
	g.IDs = appendUnique(g.IDs, f.ID)
	g.Targets = appendUnique(g.Targets, f.Target)
	g.Installed = appendUnique(g.Installed, f.Installed)
}

func appendUnique(ss []string, s string) []string {
	for _, x := range ss {
		if x == s {
			return ss
		}
	}
	return append(ss, s)
}
