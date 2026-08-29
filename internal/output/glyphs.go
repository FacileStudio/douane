package output

import (
	"io"
	"os"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

// glyphs are the marks and separators, with an ASCII fallback for terminals
// that cannot be trusted with box drawing. Same vocabulary as filet, because
// the two tools are read in the same terminal on the same day.
type glyphs struct {
	Mark  string
	Arrow string
	Sep   string
	To    string
	None  string
}

var (
	unicodeGlyphs = glyphs{Mark: "◆", Arrow: "↳", Sep: "·", To: "→", None: "—"}
	asciiGlyphs   = glyphs{Mark: ">", Arrow: "->", Sep: "|", To: "->", None: "-"}
)

// glyphsFor picks the richest character set the environment claims to handle.
// A terminal that never declared a UTF-8 locale gets ASCII: a mojibake diamond
// is worse than a plain one.
func glyphsFor(w io.Writer) glyphs {
	if !isTTY(w) || !utf8Locale() {
		return asciiGlyphs
	}
	return unicodeGlyphs
}

func utf8Locale() bool {
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := os.Getenv(key); v != "" {
			up := strings.ToUpper(v)
			return strings.Contains(up, "UTF-8") || strings.Contains(up, "UTF8")
		}
	}
	return false
}

// severityColour is a ramp, not an alarm. Only critical is red; high is amber,
// medium is blue and everything below is grey. The fleet is 136 critical
// against 1632 high and 1707 medium, so a palette where high and medium are
// both hot paints 87% of the report in warning colours and ranks nothing. A
// ramp keeps severity legible at a glance while leaving red meaning red.
func severityColour(s finding.Severity) string {
	switch s {
	case finding.SevCritical:
		return ansiRed
	case finding.SevHigh:
		return ansiYellow
	case finding.SevMedium:
		return ansiBlue
	default:
		return ansiGrey
	}
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
