package cli

import (
	"os"
	"path/filepath"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/output"
	"github.com/FacileStudio/douane/internal/store"
)

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

func defaultDB() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "douane.db"
	}
	return filepath.Join(home, ".douane.db")
}

func parseFail(s string) (int, bool) {
	switch s {
	case "never":
		return 99, true
	case "kev":
		return 98, true
	case "low":
		return int(finding.SevLow), true
	case "medium":
		return int(finding.SevMedium), true
	case "high":
		return int(finding.SevHigh), true
	case "critical":
		return int(finding.SevCritical), true
	}
	return 0, false
}

func shouldFail(fs []finding.Finding, threshold int) bool {
	for _, f := range fs {
		if threshold == 98 && f.Exploit.KEV {
			return true
		}
		if threshold < 98 && int(f.Severity) >= threshold {
			return true
		}
	}
	return false
}
