package finding

import "fmt"

// GapKind names what douane was unable to determine.
type GapKind string

// The kinds of gap douane can report. Each one marks a place where an answer
// was expected and none arrived, so that an absent answer is never mistaken
// for the absence of a problem.
const (
	GapUpstream    GapKind = "upstream"
	GapUnreadable  GapKind = "unreadable"
	GapUnsupported GapKind = "unsupported"
	GapUnresolved  GapKind = "unresolved"
	GapSeverity    GapKind = "severity"
	GapRange       GapKind = "range"
)

// Gap is one thing douane could not determine. It exists because the three
// older ways of saying so — a warning string, a Failed flag, and a finding
// simply being absent — all render an incomplete scan as a clean one.
type Gap struct {
	Kind    GapKind `json:"kind"`
	Subject string  `json:"subject"`
	Detail  string  `json:"detail"`
}

// String renders a gap as the one line a reader needs.
func (g Gap) String() string {
	if g.Subject == "" {
		return fmt.Sprintf("%s: %s", g.Kind, g.Detail)
	}
	return fmt.Sprintf("%s: %s: %s", g.Kind, g.Subject, g.Detail)
}

// Gaps renders a list of gaps as their lines, in order.
func Gaps(gs []Gap) []string {
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.String())
	}
	return out
}
