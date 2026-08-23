package output

import (
	"encoding/json"
	"io"

	"github.com/FacileStudio/douane/internal/finding"
)

// SchemaVersion names the shape of the json output. It is emitted once, at the
// root, so a pipeline that pins it is told when a field moves rather than
// discovering it against production.
const SchemaVersion = "1"

// findingJSON is a finding as a consumer needs it: carrying the key douane's
// history is keyed by, and whether this run is the first to have seen it. New
// used to live on the report as a map tagged json:"-", so the one signal the
// tool exists for never reached the format CI parses.
type findingJSON struct {
	finding.Finding
	Key string `json:"key"`
	New bool   `json:"new"`
}

// reportJSON is one scan as json. Complete is the field that separates
// "nothing held" from "douane could not tell", and findings and gaps are
// always arrays so a consumer can count them without a null check.
type reportJSON struct {
	SchemaVersion string        `json:"schema_version,omitempty"`
	Name          string        `json:"name,omitempty"`
	Target        string        `json:"target"`
	Packages      int           `json:"packages"`
	Complete      bool          `json:"complete"`
	Failed        bool          `json:"failed,omitempty"`
	Findings      []findingJSON `json:"findings"`
	Gaps          []finding.Gap `json:"gaps"`
	Warnings      []string      `json:"warnings,omitempty"`
}

type sweepJSON struct {
	SchemaVersion string        `json:"schema_version"`
	Root          string        `json:"root"`
	Complete      bool          `json:"complete"`
	Repos         []reportJSON  `json:"repos"`
	Gaps          []finding.Gap `json:"gaps"`
	Warnings      []string      `json:"warnings,omitempty"`
}

// reportBody renders a report's json shape without the schema version, which only
// the root document carries: repeating it once per repository in a fleet run
// would be noise every consumer pays for.
func reportBody(r Report) reportJSON {
	fs := make([]findingJSON, 0, len(r.Findings))
	for _, f := range r.Findings {
		fs = append(fs, findingJSON{Finding: f, Key: f.Key(), New: r.New[f.Key()]})
	}
	gaps := r.Gaps
	if gaps == nil {
		gaps = []finding.Gap{}
	}
	return reportJSON{Name: r.Name, Target: r.Target, Packages: r.Packages,
		Complete: r.Complete(), Failed: r.Failed, Findings: fs, Gaps: gaps,
		Warnings: r.Warnings}
}

// MarshalJSON emits a scan as its own document, schema version and all.
func (r Report) MarshalJSON() ([]byte, error) {
	b := reportBody(r)
	b.SchemaVersion = SchemaVersion
	return json.Marshal(b)
}

// MarshalJSON emits a fleet run, complete when no repository in it left a gap.
func (s Sweep) MarshalJSON() ([]byte, error) {
	repos := make([]reportJSON, 0, len(s.Repos))
	for _, r := range s.Repos {
		repos = append(repos, reportBody(r))
	}
	gaps := s.Gaps
	if gaps == nil {
		gaps = []finding.Gap{}
	}
	return json.Marshal(sweepJSON{SchemaVersion: SchemaVersion, Root: s.Root,
		Complete: s.Complete(), Repos: repos, Gaps: gaps, Warnings: s.Warnings})
}

func encodeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
