package output

import (
	"fmt"
	"io"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/permit"
)

// permitJSON is a permit as a consumer reads it: the expiry as the date the
// author wrote, not a timestamp at midnight UTC.
type permitJSON struct {
	ID      string `json:"id"`
	Package string `json:"package,omitempty"`
	Reason  string `json:"reason"`
	Expires string `json:"expires"`
	Line    int    `json:"line"`
}

// permittedJSON is a finding a valid permit took out of the report, with the
// permit that did it, so the suppression stays auditable from the json alone.
type permittedJSON struct {
	finding.Finding
	Key    string     `json:"key"`
	Permit permitJSON `json:"permit"`
}

func permittedBody(ms []permit.Match) []permittedJSON {
	out := make([]permittedJSON, 0, len(ms))
	for _, m := range ms {
		p := m.Permit
		out = append(out, permittedJSON{Finding: m.Finding, Key: m.Finding.Key(), Permit: permitJSON{
			ID: p.ID, Package: p.Package, Reason: p.Reason,
			Expires: p.Expires.Format("2006-01-02"), Line: p.Line,
		}})
	}
	return out
}

func expiredFn(r Report) func(finding.Finding) bool {
	return func(f finding.Finding) bool { return r.Expired[f.Key()] }
}

// permitTag is the line format's marker for a finding a lapsed permit gave
// back. It is appended inside the bracket only when set, so a line with no
// permit involved reads exactly as it always has.
func permitTag(expired bool) string {
	if expired {
		return " permit=expired"
	}
	return ""
}

// writePermitNotes sends what a run says about its permits to the notes
// stream, in every format. A permit about to lapse is news for the human
// reading a terminal and for the CI log alike, and neither stdout grammar has
// room for it.
func writePermitNotes(w io.Writer, prefix string, notes []string) error {
	for _, n := range notes {
		if _, err := fmt.Fprintf(w, "douane: %s%s\n", prefix, n); err != nil {
			return err
		}
	}
	return nil
}

func writeSweepPermitNotes(w io.Writer, s Sweep) error {
	for _, r := range s.Repos {
		if err := writePermitNotes(w, r.Name+": ", r.PermitNotes); err != nil {
			return err
		}
	}
	return nil
}
