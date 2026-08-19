package output

import (
	"encoding/json"
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

// Report is one sweep's result, ready to render.
type Report struct {
	Name     string            `json:"name,omitempty"`
	Target   string            `json:"target"`
	Packages int               `json:"packages"`
	Failed   bool              `json:"failed,omitempty"`
	Findings []finding.Finding `json:"findings"`
	New      map[string]bool   `json:"-"`
	Warnings []string          `json:"warnings,omitempty"`
}

// Write renders the report in the given format.
func Write(w io.Writer, f Format, r Report) error {
	switch f {
	case JSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case Line:
		return writeLine(w, r)
	default:
		return writeText(w, r)
	}
}

func writeLine(w io.Writer, r Report) error {
	return writeLinePrefixed(w, "", r)
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
	for _, warn := range r.Warnings {
		if _, err := fmt.Fprintf(w, "douane: warning: %s%s\n", prefix, warn); err != nil {
			return err
		}
	}
	return nil
}
