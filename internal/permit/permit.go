// Package permit reads douane.yml, the file that suppresses a finding for a
// stated reason until a stated date. A suppression with no end date is how a
// finding vanishes for good while the tool keeps saying the project is clean,
// so every permit carries both, and a permit that lapses brings its finding
// back loudly instead of quietly.
package permit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// FileName is the permit file douane reads at the root of a scanned project.
const FileName = "douane.yml"

// MaxAhead is the furthest a permit may expire from the day it is read. A
// permit is temporary by definition, and a date years out is a permanent
// suppression wearing a costume.
const MaxAhead = 365 * 24 * time.Hour

// Soon is the window inside which a permit about to lapse is announced on
// every run, so its owner renews or fixes it before CI turns red.
const Soon = 14 * 24 * time.Hour

// Permit is one entry of douane.yml. ID matches any name the finding goes by;
// Package, when set, narrows the match to one package. Expires is the last day
// the permit holds. Line is where the entry starts, for every message about it.
type Permit struct {
	ID      string
	Package string
	Reason  string
	Expires time.Time
	Line    int
}

// Lapsed reports whether the permit no longer holds on today. The expiry date
// itself is the permit's last valid day.
func (p Permit) Lapsed(today time.Time) bool { return today.After(p.Expires) }

// Error is a douane.yml that douane refuses to read, naming the line at fault.
type Error struct {
	Line int
	Msg  string
}

// Error renders the line and the reason, ready to be prefixed with the path.
func (e *Error) Error() string { return fmt.Sprintf("%d: %s", e.Line, e.Msg) }

// Today is the current calendar day, as a UTC midnight so it compares directly
// against the dates douane.yml carries.
func Today() time.Time {
	y, m, d := time.Now().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// Load reads dir's douane.yml. A project without one has no permits, which is
// not an error. A file that is present but invalid is, and its message carries
// the path and the line, because a permit douane silently skipped would
// reinstate a finding the author believes is handled.
func Load(dir string, today time.Time) ([]Permit, error) {
	if info, err := os.Stat(dir); err == nil && !info.IsDir() {
		return nil, nil
	}
	path := filepath.Join(dir, FileName)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	permits, err := Parse(data, today)
	if err != nil {
		return nil, fmt.Errorf("%s:%w", path, err)
	}
	return permits, nil
}
