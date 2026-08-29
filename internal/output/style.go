package output

import (
	"io"
	"os"

	"github.com/FacileStudio/douane/internal/finding"
)

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
	ansiGrey   = "\033[90m"
)

// epssNotable is where exploit probability stops being noise. Measured over
// the fleet on 2026-08-28: 16 findings of 3816 sit at or above 5%, 101 above
// 1%, and the rest are indistinguishable from zero. Below this a score is
// printed but never highlighted.
const epssNotable = 0.05

// style paints the human report. It is per-writer rather than a package-level
// flag because douane sends findings to one stream and notes to another:
// `douane sweep > report.txt` should still colour the gaps it puts on the
// terminal while leaving the file plain.
type style struct{ on bool }

// newStyle decides whether w gets ANSI. A bytes.Buffer is never a terminal, so
// every test renders plain and the byte-pinned line-format contracts keep
// passing without being told about colour at all.
func newStyle(w io.Writer) style {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return style{}
	}
	return style{on: isTTY(w)}
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// paint wraps text, never padding. Callers pad first and paint second: an
// escape sequence counts toward a %-9s width and would silently shear every
// column in the report.
func (s style) paint(code, text string) string {
	if !s.on || text == "" {
		return text
	}
	return code + text + ansiReset
}

// dim carries what a reader scans past on the way to a decision: advisory ids,
// targets, ecosystems, prose.
func (s style) dim(text string) string { return s.paint(ansiDim, text) }

// bold carries what the eye should land on first: the severity word and the
// package name.
func (s style) bold(text string) string { return s.paint(ansiBold, text) }

// fix carries the version that clears the finding, which is the action the
// whole report exists to name.
func (s style) fix(text string) string { return s.paint(ansiGreen, text) }

// alarm is what douane's own ranking calls exceptional: a KEV hit or
// ransomware. Severity gets its own ramp in severityColour, which reaches red
// only at critical, so red keeps meaning red in both places.
func (s style) alarm(text string) string { return s.paint(ansiRed, text) }

// mark paints a severity glyph. Hue rides the mark rather than the whole line,
// so severity stays scannable without 3400 findings' worth of coloured prose.
func (s style) mark(sev finding.Severity, text string) string {
	return s.paint(severityColour(sev), text)
}

// warn carries the second tier: new since the last run, no fix available, and
// an exploit probability above epssNotable.
func (s style) warn(text string) string { return s.paint(ansiYellow, text) }
