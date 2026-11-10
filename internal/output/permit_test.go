package output_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/output"
	"github.com/FacileStudio/douane/internal/permit"
)

func permitted() output.Report {
	kept, gone := outFinding("GO-1"), outFinding("GO-2")
	r := outReport()
	r.Findings = []finding.Finding{kept}
	r.Expired = map[string]bool{kept.Key(): true}
	r.Permitted = []permit.Match{{Finding: gone, Permit: permit.Permit{ID: "GO-2", Reason: "not reachable",
		Expires: time.Date(2027, 1, 31, 0, 0, 0, 0, time.UTC), Line: 3}}}
	r.PermitNotes = []string{"EXPIRED PERMIT: GO-1 on chi lapsed 2026-11-01, the finding is back (douane.yml:7)"}
	return r
}

func TestJSONListsPermittedAndMarksExpired(t *testing.T) {
	stdout, _ := outWriteTo(t, output.JSON, output.LayoutFix, permitted())
	var doc struct {
		Findings []struct {
			ID            string `json:"id"`
			ExpiredPermit bool   `json:"expired_permit"`
		} `json:"findings"`
		Permitted []struct {
			ID     string `json:"id"`
			Permit struct {
				Reason  string `json:"reason"`
				Expires string `json:"expires"`
			} `json:"permit"`
		} `json:"permitted"`
		Groups []finding.Group `json:"groups"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("decode %s: %v", stdout, err)
	}
	if len(doc.Findings) != 1 || !doc.Findings[0].ExpiredPermit || doc.Groups[0].Expired != 1 {
		t.Fatalf("findings = %+v, groups = %+v; want the one finding marked expired", doc.Findings, doc.Groups)
	}
	if len(doc.Permitted) != 1 || doc.Permitted[0].ID != "GO-2" || doc.Permitted[0].Permit.Expires != "2027-01-31" {
		t.Fatalf("permitted = %+v, want GO-2 with its permit", doc.Permitted)
	}
}

func TestTextMarksExpiredAndKeepsPermitNotesOffStdout(t *testing.T) {
	for _, l := range []output.Layout{output.LayoutFix, output.LayoutFinding} {
		stdout, stderr := outWriteTo(t, output.Text, l, permitted())
		if !strings.Contains(stdout, "EXPIRED PERMIT") || strings.Contains(stdout, "douane.yml") {
			t.Fatalf("%s stdout = %q, want the marker and no permit note", l, stdout)
		}
		if !strings.HasPrefix(stderr, "douane: EXPIRED PERMIT: GO-1") {
			t.Fatalf("%s stderr = %q, want the permit note", l, stderr)
		}
	}
}

func TestEmptyPermittedIsAnArray(t *testing.T) {
	stdout, _ := outWriteTo(t, output.JSON, output.LayoutFix, outReport())
	if !strings.Contains(stdout, `"permitted": []`) {
		t.Fatalf("json = %s, want permitted as an empty array", stdout)
	}
}
