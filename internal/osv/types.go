package osv

// Event is one point on an affected-version range: a version that introduced
// the flaw, or one that fixed it.
type Event struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

// Range is a contiguous span of affected versions for one package branch.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// PackageRef names a package within an ecosystem.
type PackageRef struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// Affected ties a package to the version ranges an advisory covers.
type Affected struct {
	Package PackageRef `json:"package"`
	Ranges  []Range    `json:"ranges"`
}

// SeverityScore is one scoring of an advisory, such as a CVSS vector.
type SeverityScore struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// DatabaseSpecific carries fields the source database adds outside the schema.
type DatabaseSpecific struct {
	Severity string `json:"severity"`
}

// Vuln is the subset of an OSV record douane consumes.
type Vuln struct {
	ID               string           `json:"id"`
	Summary          string           `json:"summary"`
	Aliases          []string         `json:"aliases"`
	Severity         []SeverityScore  `json:"severity"`
	DatabaseSpecific DatabaseSpecific `json:"database_specific"`
	Affected         []Affected       `json:"affected"`
}
