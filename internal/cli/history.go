package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/output"
	"github.com/FacileStudio/douane/internal/store"
)

// Process exit codes. 3 exists so that CI can tell "you are vulnerable", which
// is final, from "douane could not determine part of the answer", which is
// worth retrying before it blocks.
const (
	exitClear      = 0
	exitFindings   = 1
	exitUsage      = 2
	exitIncomplete = 3
)

// threshold is what -fail was set to. It is a type rather than a magic int
// because "fail on anything" and "fail only on KEV" are not points on the
// severity scale and pretending otherwise is how they got compared with <.
type threshold struct {
	severity finding.Severity
	kev      bool
	any      bool
	never    bool
}

// history marks findings unseen by the previous sweep of this target and
// records the current one. The store is passed in already open: a fleet sweep
// reuses one handle for every repo, and it is the same handle the feed cache
// lives in.
func history(st *store.Store, report *output.Report) error {
	previous, err := st.PreviousKeys(report.Target)
	if err != nil {
		return err
	}
	for _, f := range report.Findings {
		if !previous[f.Key()] {
			report.New[f.Key()] = true
		}
	}
	return st.Save(report.Target, report.Packages, report.Findings)
}

// record files this run so the next one can say what is new. A history that
// cannot be written costs the NEW badge, never the scan, so it degrades to a
// warning rather than an exit code.
func record(st *store.Store, report *output.Report) {
	if st == nil {
		return
	}
	if err := history(st, report); err != nil {
		report.Warnings = append(report.Warnings,
			fmt.Sprintf("sweep history unavailable: %v", err))
	}
}

func defaultDB() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "douane.db"
	}
	return filepath.Join(home, ".douane.db")
}

func parseFail(s string) (threshold, bool) {
	switch s {
	case "never":
		return threshold{never: true}, true
	case "any":
		return threshold{any: true}, true
	case "kev":
		return threshold{kev: true}, true
	case "low":
		return threshold{severity: finding.SevLow}, true
	case "medium":
		return threshold{severity: finding.SevMedium}, true
	case "high":
		return threshold{severity: finding.SevHigh}, true
	case "critical":
		return threshold{severity: finding.SevCritical}, true
	}
	return threshold{}, false
}

func shouldFail(fs []finding.Finding, t threshold) bool {
	if t.never {
		return false
	}
	for _, f := range fs {
		switch {
		case t.any:
			return true
		case t.kev && f.Exploit.KEV:
			return true
		case !t.kev && f.Severity >= t.severity:
			return true
		}
	}
	return false
}

// exitFor ranks the two ways a run can be bad. Findings above the threshold
// outrank an incomplete scan: both block, but "you are vulnerable" is a
// finished answer and there is nothing to retry.
func exitFor(fs []finding.Finding, gaps []finding.Gap, t threshold) int {
	if shouldFail(fs, t) {
		return exitFindings
	}
	if !t.never && len(gaps) > 0 {
		return exitIncomplete
	}
	return exitClear
}
