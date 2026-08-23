package output

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

// Format selects how findings are rendered.
type Format string

// Supported output formats. Auto resolves to Text on a terminal and Line
// everywhere else, so piped and agent-driven runs get the parseable form.
const (
	Auto Format = "auto"
	Text Format = "text"
	Line Format = "line"
	JSON Format = "json"
)

// Resolve turns Auto into a concrete format based on whether w is a terminal.
func Resolve(f Format, w *os.File) Format {
	if f != Auto {
		return f
	}
	info, err := w.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return Line
	}
	return Text
}

// Report is one sweep's result, ready to render. The json tags below are the
// field names; the document a consumer actually receives is assembled in
// json.go, which adds what a struct tag cannot say.
type Report struct {
	Name     string            `json:"name,omitempty"`
	Target   string            `json:"target"`
	Packages int               `json:"packages"`
	Failed   bool              `json:"failed,omitempty"`
	Findings []finding.Finding `json:"findings"`
	New      map[string]bool   `json:"-"`
	Gaps     []finding.Gap     `json:"gaps,omitempty"`
	Warnings []string          `json:"warnings,omitempty"`
}

// Complete reports whether douane determined everything it set out to. An
// incomplete report may be missing findings it never got to see, so a -fail
// threshold cannot be honoured over it.
func (r Report) Complete() bool { return len(r.Gaps) == 0 }

// Write renders the report in the given format, everything on w. WriteTo is
// the form that keeps a parser's stream clean.
func Write(w io.Writer, f Format, r Report) error { return WriteTo(w, w, f, r) }

// WriteTo renders the report, sending the data to out and the notes — gaps and
// warnings — to errw. In line and json form that separation is the whole
// point: what stdout carries is then findings and nothing else, and a warning
// can no longer be mistaken for one by whatever is grepping the stream. Text
// is a single narrative for a human, so it stays on one writer.
func WriteTo(out, errw io.Writer, f Format, r Report) error {
	if f == JSON || f == Line {
		if err := writeNotes(errw, "", r.Gaps, r.Warnings); err != nil {
			return err
		}
	}
	switch f {
	case JSON:
		return encodeJSON(out, r)
	case Line:
		return writeLinePrefixed(out, "", r)
	default:
		return writeText(out, r)
	}
}

// writeLinePrefixed renders the greppable form, tagging every line with prefix
// so a fleet sweep says which repo a finding came from.
func writeLinePrefixed(w io.Writer, prefix string, r Report) error {
	for _, f := range r.Findings {
		fix := f.FixedIn
		if fix == "" {
			fix = "no-fix"
		}
		if _, err := fmt.Fprintf(w, "%s%s:%s@%s: %s: %s [%s epss=%.4f kev=%t fix=%s]\n",
			prefix, f.Ecosystem, f.Package, f.Installed, strings.ToLower(f.Severity.String()),
			f.ID, f.Target, f.Exploit.EPSS, f.Exploit.KEV, fix); err != nil {
			return err
		}
	}
	return nil
}
