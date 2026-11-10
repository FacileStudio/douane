package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/FacileStudio/douane/internal/output"
	"github.com/FacileStudio/douane/internal/permit"
)

// loadPermits reads the douane.yml at dir. A file douane refuses is a usage
// error, reported with its path and line before any network call is made:
// running on while ignoring a permit would print a finding its author believes
// is handled, and running on while ignoring the whole file would print all of
// them.
func loadPermits(dir string, today time.Time) ([]permit.Permit, bool) {
	ps, err := permit.Load(dir, today)
	if err != nil {
		fmt.Fprintf(os.Stderr, "douane: %v\n", err)
		return nil, false
	}
	return ps, true
}

// attachPermits gives every repository of a sweep its own douane.yml, and
// nobody else's: a permit is a decision about one project.
func attachPermits(repos []*repoScan, today time.Time) bool {
	for _, r := range repos {
		ps, ok := loadPermits(r.report.Target, today)
		if !ok {
			return false
		}
		r.permits = ps
	}
	return true
}

// applyPermits takes the findings a valid permit covers out of the report and
// marks the ones a lapsed permit gave back. It runs after the history is
// recorded, so a permit hides a finding from the output and never from the
// record of what the project carries.
func applyPermits(report *output.Report, ps []permit.Permit, today time.Time) {
	out := permit.Apply(report.Findings, ps, today)
	report.Findings = out.Kept
	report.Permitted = out.Permitted
	report.Expired = map[string]bool{}
	for _, m := range out.Expired {
		report.Expired[m.Finding.Key()] = true
	}
	report.PermitNotes = permit.Notes(out, ps, today)
}

// permitExit fails a run that holds a finding a lapsed permit gave back,
// whatever -fail says. The author of the permit promised to look again by that
// date, and a gate that stays green past it is the silent suppression permits
// exist to replace.
func permitExit(code int, reports ...output.Report) int {
	for _, r := range reports {
		if len(r.Expired) > 0 {
			return exitFindings
		}
	}
	return code
}
