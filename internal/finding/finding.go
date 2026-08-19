package finding

import "sort"

// Severity is the coarse impact rating carried by an advisory.
type Severity int

// Severity levels, ordered so that a higher value is worse.
const (
	SevUnknown Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

// ParseSeverity maps an advisory's textual severity onto a Severity.
func ParseSeverity(s string) Severity {
	switch s {
	case "CRITICAL":
		return SevCritical
	case "HIGH":
		return SevHigh
	case "MODERATE", "MEDIUM":
		return SevMedium
	case "LOW":
		return SevLow
	}
	return SevUnknown
}

// MarshalJSON emits a Severity as its uppercase word rather than its ordinal.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// String renders a Severity as the uppercase word used in output.
func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	case SevLow:
		return "LOW"
	}
	return "UNKNOWN"
}

// Package is one resolved dependency read out of a lockfile.
type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Version   string `json:"version"`
	Source    string `json:"source"`
}

// Exploit groups the signals that say whether a flaw is likely to hurt in
// practice, as opposed to how bad it would be if it did.
type Exploit struct {
	KEV        bool    `json:"kev"`
	Ransomware bool    `json:"kev_ransomware,omitempty"`
	EPSS       float64 `json:"epss"`
	EPSSKnown  bool    `json:"epss_known"`
	Reachable  *bool   `json:"reachable"`
}

// Finding is one vulnerability affecting one package, after alias resolution
// and enrichment. It is the only shape the rest of douane passes around.
type Finding struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases,omitempty"`
	Summary   string   `json:"summary"`
	Severity  Severity `json:"severity"`
	CVSS      string   `json:"cvss,omitempty"`
	Package   string   `json:"package"`
	Ecosystem string   `json:"ecosystem"`
	Installed string   `json:"installed"`
	FixedIn   string   `json:"fixed_in"`
	Exploit   Exploit  `json:"exploit"`
	Target    string   `json:"target"`
	Sources   []string `json:"sources"`
}

// HasFix reports whether an upgrade path out of this finding exists at all.
// An empty FixedIn is a different decision from an available-but-untaken fix.
func (f Finding) HasFix() bool { return f.FixedIn != "" }

// Key identifies a finding uniquely within one sweep.
func (f Finding) Key() string {
	return f.Ecosystem + "|" + f.Package + "|" + f.Installed + "|" + f.ID
}

// Rank sorts findings by what should be acted on first: known-exploited,
// then likelihood of exploitation, then severity, then a stable tiebreak.
func Rank(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool { return Less(fs[i], fs[j]) })
}

// Less reports whether a should be acted on before b. It is what Rank sorts
// by, exported so a fleet report can order repos by their worst finding
// without a second, quietly different, notion of "worst".
func Less(a, b Finding) bool {
	switch {
	case a.Exploit.KEV != b.Exploit.KEV:
		return a.Exploit.KEV
	case a.Exploit.EPSS != b.Exploit.EPSS:
		return a.Exploit.EPSS > b.Exploit.EPSS
	case a.Severity != b.Severity:
		return a.Severity > b.Severity
	case a.Package != b.Package:
		return a.Package < b.Package
	}
	return a.ID < b.ID
}
