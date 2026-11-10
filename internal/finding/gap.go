package finding

import (
	"fmt"
	"slices"
)

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
// Advisory is set only on a gap that exists because of one advisory's
// findings, never on a gap about the scan itself, and is what lets a permit
// for those findings cover it. Annotation is set on a gap about something
// douane adds to the findings it did report, a KEV or EPSS score or the
// release line a Dockerfile builds with, never on one about which findings
// exist.
type Gap struct {
	Kind       GapKind `json:"kind"`
	Subject    string  `json:"subject"`
	Detail     string  `json:"detail"`
	Advisory   string  `json:"-"`
	Annotation bool    `json:"-"`
}

// HidesFindings is the one place gaps are classified by what they can cost.
// It reports whether g can stand for findings douane never saw: a vulnerability
// query that failed, a lockfile it could not read or does not support, an
// advisory or package it could not resolve. Those keep a run from writing the
// history it would compare the next one against. A severity or range gap only
// qualifies a finding that was reported, and an annotation gap only a label on
// one, so neither hides anything. An unknown kind hides, because guessing the
// other way would let a new kind of hole pass as a complete answer.
func (g Gap) HidesFindings() bool {
	switch g.Kind {
	case GapSeverity, GapRange:
		return false
	case GapUpstream, GapUnreadable, GapUnsupported, GapUnresolved:
		return !g.Annotation
	}
	return true
}

// Concerns reports whether g exists only because of f. A range gap is about
// one package as well as one advisory, so it concerns only that package's
// finding; every other advisory gap concerns each finding the advisory names.
// A gap about the scan, a lockfile or a feed concerns no finding at all.
func (g Gap) Concerns(f Finding) bool {
	if g.Advisory == "" || !slices.Contains(f.Names(), g.Advisory) {
		return false
	}
	return g.Kind != GapRange || g.Subject == f.Package
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
