package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/output"
	"github.com/FacileStudio/douane/internal/permit"
)

const unratedID = "GO-2026-5932"

const unratedRecord = `{"id":"GO-2026-5932","summary":"unrated","affected":[{"package":` +
	`{"ecosystem":"Go","name":"golang.org/x/crypto"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`

func serveUnrated(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/vulns/"+unratedID) {
		w.Write([]byte(unratedRecord))
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/querybatch") {
		http.Error(w, `{"code":5,"message":"Bug not found."}`, http.StatusNotFound)
		return
	}
	var req batchRequest
	json.NewDecoder(r.Body).Decode(&req)
	results := make([]map[string]any, 0, len(req.Queries))
	for range req.Queries {
		results = append(results, map[string]any{"vulns": []map[string]string{{"id": unratedID}}})
	}
	json.NewEncoder(w).Encode(map[string]any{"results": results})
}

func cryptoRepo(name string) *repoScan {
	r := &repoScan{report: output.Report{Name: name, Target: "/" + name, New: map[string]bool{}}}
	r.pkgs = []finding.Package{{Name: "golang.org/x/crypto", Ecosystem: "Go", Version: "0.31.0", Source: "go.mod"}}
	r.report.Packages = 1
	return r
}

func unratedPermit() []permit.Permit {
	return []permit.Permit{{ID: unratedID, Reason: "not imported", Expires: permit.Today().AddDate(0, 1, 0), Line: 2}}
}

func TestAPermitCoversTheGapItsFindingRaised(t *testing.T) {
	r := cryptoRepo("app")
	resolve(context.Background(), fakeOSV(t, serveUnrated), r.pkgs, &r.report)
	if len(r.report.Gaps) != 1 || r.report.Gaps[0].Kind != finding.GapSeverity {
		t.Fatalf("gaps = %v, want the one severity gap the unrated advisory raises", r.report.Gaps)
	}
	applyPermits(&r.report, unratedPermit(), permit.Today())
	if code := exitFor(r.report.Findings, r.report.Gaps, threshold{severity: finding.SevCritical}); code != exitClear {
		t.Fatalf("exit = %d, want %d: the only gap belongs to a permitted finding", code, exitClear)
	}
	body, _ := json.Marshal(r.report)
	var got struct {
		Complete  bool `json:"complete"`
		Permitted []struct {
			Gaps []finding.Gap `json:"gaps"`
		} `json:"permitted"`
	}
	json.Unmarshal(body, &got)
	if !got.Complete || len(got.Permitted) != 1 || len(got.Permitted[0].Gaps) != 1 {
		t.Fatalf("json = %s, want the gap listed under its permitted finding", body)
	}
}

func TestAFleetGapStandsWhileAnyRepoStillHoldsItsFinding(t *testing.T) {
	for _, tc := range []struct {
		name string
		want int
		bare bool
	}{{"one permitted repo", exitClear, false}, {"one repo without a permit", exitIncomplete, true}} {
		permitted := cryptoRepo("permitted")
		permitted.permits = unratedPermit()
		repos := []*repoScan{permitted}
		if tc.bare {
			repos = append(repos, cryptoRepo("bare"))
		}
		var sweep output.Sweep
		resolveFleet(context.Background(), fakeOSV(t, serveUnrated), repos, &sweep)
		collect(repos, nil, &sweep, finding.FilterAll, "warn")
		if code := sweepExit(sweep, threshold{severity: finding.SevCritical}); code != tc.want {
			t.Fatalf("%s: exit = %d, want %d (gaps %v)", tc.name, code, tc.want, sweep.AllGaps())
		}
	}
}

func TestAPermitNeverCoversAGapAboutTheScan(t *testing.T) {
	r := permitReport()
	r.Gaps = []finding.Gap{{Kind: finding.GapUnresolved, Subject: "GO-2026-1", Detail: "fetch failed"}}
	applyPermits(&r, []permit.Permit{{ID: "GO-2026-1", Reason: "r", Expires: permit.Today().AddDate(0, 1, 0)}},
		permit.Today())
	if code := exitFor(r.Findings, r.Gaps, threshold{severity: finding.SevCritical}); code != exitIncomplete {
		t.Fatalf("exit = %d, want %d: a failed fetch is about the scan, not the finding", code, exitIncomplete)
	}
}

func TestARangeGapIsCoveredOnlyForItsOwnPackage(t *testing.T) {
	r := permitReport()
	other := r.Findings[0]
	other.Package = "golang.org/x/net"
	r.Findings = append(r.Findings, other)
	gap := finding.Gap{Kind: finding.GapRange, Subject: other.Package, Detail: "commit ranges", Advisory: "GO-2026-1"}
	r.Gaps = []finding.Gap{gap}
	ps := []permit.Permit{{ID: "GO-2026-1", Package: "golang.org/x/crypto", Reason: "r",
		Expires: permit.Today().AddDate(0, 1, 0)}}
	applyPermits(&r, ps, permit.Today())
	if len(r.Gaps) != 1 || len(r.Permitted) != 1 || len(r.Permitted[0].Gaps) != 0 {
		t.Fatalf("gaps = %v, permitted = %+v; want x/net's range gap to stay on the report", r.Gaps, r.Permitted)
	}
}
