package output

import (
	"io"

	"github.com/FacileStudio/douane/internal/finding"
)

// theme is the palette and the character set, which are always decided
// together from the same writer and always travel together. Threading them as
// two parameters pushed the widest renderer to six arguments; embedding both
// keeps every signature short and lets a caller write th.dim(th.Sep) without
// knowing which half it came from.
type theme struct {
	style
	glyphs
}

func newTheme(w io.Writer) theme {
	return theme{style: newStyle(w), glyphs: glyphsFor(w)}
}

// mark paints a severity glyph. Hue rides the mark rather than the whole line,
// so severity stays scannable without 3400 findings' worth of coloured prose.
func (t theme) mark(sev finding.Severity, text string) string {
	return t.paint(severityColour(sev), text)
}
