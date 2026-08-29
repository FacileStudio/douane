package output

import (
	"bytes"
	"regexp"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
)

var ansiSeq = regexp.MustCompile("\x1b\\[[0-9]*m")

func styleFinding() finding.Finding {
	return finding.Finding{
		ID: "GO-1", Package: "chi", Ecosystem: "Go", Installed: "5.0.0",
		FixedIn: "5.0.12", Severity: finding.SevHigh, Target: "go.mod",
		Summary: "a thing", Exploit: finding.Exploit{KEV: true, EPSS: 0.42, EPSSKnown: true},
	}
}

// TestColorChangesOnlyEscapeBytes is the whole contract, and it catches the one
// mistake that is invisible by eye: painting before padding. An escape sequence
// counts toward a %-9s width, so a renderer that pads a coloured string shears
// every column to the right of it while still looking plausible in a terminal.
// Stripping the escapes must give back the plain render byte for byte.
func TestColorChangesOnlyEscapeBytes(t *testing.T) {
	f := styleFinding()
	g := finding.Groups([]finding.Finding{f}, func(finding.Finding) bool { return true })[0]

	for _, tc := range []struct {
		name  string
		write func(*bytes.Buffer, style)
	}{
		{"finding", func(b *bytes.Buffer, st style) { writeFinding(b, st, f, true) }},
		{"group", func(b *bytes.Buffer, st style) { writeGroup(b, st, g) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var plain, painted bytes.Buffer
			tc.write(&plain, style{})
			tc.write(&painted, style{on: true})

			if painted.String() == plain.String() {
				t.Fatal("style{on: true} emitted no escape sequences")
			}
			if got := ansiSeq.ReplaceAllString(painted.String(), ""); got != plain.String() {
				t.Errorf("colour altered layout\nplain:   %q\nstripped:%q", plain.String(), got)
			}
		})
	}
}

// TestNoColorIsHonoured covers the environment half. A writer that is not a
// terminal is never painted either, which is what keeps every other test in
// this package free of escape sequences without knowing colour exists.
func TestNoColorIsHonoured(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if newStyle(nil).on {
		t.Error("NO_COLOR set, still painting")
	}
	t.Setenv("NO_COLOR", "")
	if newStyle(&bytes.Buffer{}).on {
		t.Error("a buffer is not a terminal, still painting")
	}
}
