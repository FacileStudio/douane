package finding

import (
	"encoding/json"
	"slices"
)

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

// UnmarshalJSON reads back what MarshalJSON emits, so a document douane wrote
// parses into the same severity it came from.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var word string
	if err := json.Unmarshal(b, &word); err != nil {
		return err
	}
	switch word {
	case "CRITICAL":
		*s = SevCritical
	case "HIGH":
		*s = SevHigh
	case "MEDIUM":
		*s = SevMedium
	case "LOW":
		*s = SevLow
	default:
		*s = SevUnknown
	}
	return nil
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
	Scope     Scope  `json:"scope,omitempty"`
}

// Exploit groups the signals that say whether a flaw is likely to hurt in
// practice, as opposed to how bad it would be if it did.
type Exploit struct {
	KEV        bool    `json:"kev"`
	Ransomware bool    `json:"kev_ransomware,omitempty"`
	EPSS       float64 `json:"epss"`
	EPSSKnown  bool    `json:"epss_known"`
	Reachable  *bool   `json:"reachable"`
	Scope      Scope   `json:"scope,omitempty"`
}

// Finding is one vulnerability affecting one package, after alias resolution
// and enrichment. It is the only shape the rest of douane passes around.
type Finding struct {
	ID            string   `json:"id"`
	Aliases       []string `json:"aliases,omitempty"`
	Summary       string   `json:"summary"`
	Severity      Severity `json:"severity"`
	CVSS          string   `json:"cvss,omitempty"`
	Package       string   `json:"package"`
	Ecosystem     string   `json:"ecosystem"`
	Installed     string   `json:"installed"`
	FixedIn       string   `json:"fixed_in"`
	Exploit       Exploit  `json:"exploit"`
	Target        string   `json:"target"`
	Sources       []string `json:"sources"`
	Informational string   `json:"informational,omitempty"`
}

// HasFix reports whether an upgrade path out of this finding exists at all.
// An empty FixedIn is a different decision from an available-but-untaken fix.
func (f Finding) HasFix() bool { return f.FixedIn != "" }

// Names lists every identifier the flaw goes by, sorted and without repeats.
func (f Finding) Names() []string {
	names := append([]string{f.ID}, f.Aliases...)
	slices.Sort(names)
	return slices.Compact(names)
}

// Key identifies a finding across sweeps. It is built from the smallest name
// the flaw has rather than from the identifier douane chose to report it
// under, because that choice moves: OSV answering 404 for a CVE twin on one run
// and a record on the next flips the report between the CVE and its GHSA alias,
// and a key that followed it read every flip as one finding resolved and one
// new.
func (f Finding) Key() string {
	return f.KeyAs(f.Names()[0])
}

// KeyAs is the key this finding would carry if it were filed under name. It
// reads history written before Key stopped following the reported identifier.
func (f Finding) KeyAs(name string) string {
	return f.Ecosystem + "|" + f.Package + "|" + f.Installed + "|" + name
}
