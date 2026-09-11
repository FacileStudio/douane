package finding

// Scope is how far a package reaches into a runtime. A package reachable from
// a dependency ships in the artifact; a package reachable only from a
// devDependency builds it. A named string so an unknown scope is the empty
// value, which json omitted and renderers treat as "not classified".
type Scope string

const (
	// ScopeUnknown means no lockfile carried enough to classify the package.
	// It is treated as prod everywhere, because guessing the other way hides a
	// real finding.
	ScopeUnknown Scope = ""
	// ScopeProd is a package reachable from a runtime dependency.
	ScopeProd Scope = "prod"
	// ScopeDev is a package reachable only from a devDependency.
	ScopeDev Scope = "dev"
)

// ScopeFilter is what -scope asks for. It is separate from Scope because "all"
// is a filter over findings, not a scope a finding can carry.
type ScopeFilter int

const (
	FilterAll ScopeFilter = iota
	FilterProd
	FilterDev
)

// FilterScope returns the findings that survive a -scope filter. Prod keeps
// everything that is not dev-only, so unclassified packages and every
// non-npm ecosystem pass through; dev keeps only the dev-only ones; all keeps
// everything.
func FilterScope(fs []Finding, f ScopeFilter) []Finding {
	if f == FilterAll {
		return fs
	}
	out := make([]Finding, 0, len(fs))
	for _, x := range fs {
		if (f == FilterProd && x.Exploit.Scope != ScopeDev) || (f == FilterDev && x.Exploit.Scope == ScopeDev) {
			out = append(out, x)
		}
	}
	return out
}

// FilterInformational drops informational findings when ignore is true. The
// default warn and fail modes keep them — warn so the report still shows what
// to watch, fail so the gate can escalate them — and only ignore hides them
// from the output entirely. It is opt-in, never the default, because an
// unmaintained crate that disappears from the report also disappears from the
// decision to migrate.
func FilterInformational(fs []Finding, ignore bool) []Finding {
	if !ignore {
		return fs
	}
	out := make([]Finding, 0, len(fs))
	for _, x := range fs {
		if x.Informational == "" {
			out = append(out, x)
		}
	}
	return out
}
