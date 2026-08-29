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

// Layout selects how findings are arranged: grouped by the fix that clears
// them, or one per line as they were printed before grouping existed. It is
// orthogonal to Format and never touches the json shape, which always carries
// both.
type Layout string

// Supported layouts. Fix is the default: printing the same bump once per
// repository is printing the same decision dozens of times.
const (
	LayoutFix     Layout = "fix"
	LayoutFinding Layout = "finding"
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

	// BuildLines maps a module's lockfile path to the release line its
	// Dockerfile builds it with. It lives on the report rather than on every
	// finding because it is a property of a module: one repo carried it on 121
	// findings for three modules.
	BuildLines map[string]string `json:"build_lines,omitempty"`
}

// Complete reports whether douane determined everything it set out to. An
// incomplete report may be missing findings it never got to see, so a -fail
// threshold cannot be honoured over it.
func (r Report) Complete() bool { return len(r.Gaps) == 0 }

// Write renders the report in the given format, everything on w. WriteTo is
// the form that keeps a parser's stream clean.
func Write(w io.Writer, f Format, r Report) error { return WriteTo(w, w, f, LayoutFix, r) }

// WriteTo renders the report, sending the data to out and the notes — gaps and
// warnings — to errw. In line and json form that separation is the whole
// point: what stdout carries is then findings and nothing else, and a warning
// can no longer be mistaken for one by whatever is grepping the stream. Text
// is a single narrative for a human, so it stays on one writer. The layout
// picks grouped or flat; json ignores it and always emits both shapes.
func WriteTo(out, errw io.Writer, f Format, l Layout, r Report) error {
	if f == JSON || f == Line {
		if err := writeNotes(errw, "", r.Gaps, r.Warnings); err != nil {
			return err
		}
	}
	switch f {
	case JSON:
		return encodeJSON(out, r)
	case Line:
		return writeLines(out, "", r, l)
	default:
		return writeText(out, r, l)
	}
}

// writeLines renders the greppable form. Flat mode is the historical shape,
// one line per finding tagged with prefix so a fleet sweep says which repo it
// came from; fix mode renders one line per action instead, so the fleet's
// 1965 findings stop being 1965 lines.
func writeLines(w io.Writer, prefix string, r Report, l Layout) error {
	if l == LayoutFinding {
		return writeFlatLines(w, prefix, r)
	}
	for _, g := range finding.Groups(r.Findings, isNewFn(r), rebuiltFn(r)) {
		fix := g.FixedIn
		if fix == "" {
			fix = "no-fix"
		}
		head := fmt.Sprintf("%s%s:%s@%s: %d finding%s", prefix, g.Ecosystem, g.Package,
			fix, g.Count, plural(g.Count))
		if n := len(g.Targets); n > 1 {
			head += fmt.Sprintf(" in %d targets", n)
		}
		worst := g.WorstFinding()
		if _, err := fmt.Fprintf(w, "%s: %s: worst=%s [epss=%.4f kev=%t fix=%s]\n",
			head, strings.ToLower(g.Worst.String()), worst.ID,
			worst.Exploit.EPSS, g.KEV, fix); err != nil {
			return err
		}
	}
	return nil
}

func writeFlatLines(w io.Writer, prefix string, r Report) error {
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

func isNewFn(r Report) func(finding.Finding) bool {
	return func(f finding.Finding) bool { return r.New[f.Key()] }
}

func sweepFlatLines(w io.Writer, s Sweep) error {
	for _, r := range s.Repos {
		if err := writeFlatLines(w, r.Name+": ", r); err != nil {
			return err
		}
	}
	return nil
}
