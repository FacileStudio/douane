package cli

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/output"
)

func devCryptoRepo(name string) *repoScan {
	r := cryptoRepo(name)
	r.pkgs[0].Scope = finding.ScopeDev
	return r
}

func sweepScoped(t *testing.T, repos ...*repoScan) output.Sweep {
	t.Helper()
	var sweep output.Sweep
	resolveFleet(context.Background(), fakeOSV(t, serveUnrated), repos, &sweep)
	collect(repos, nil, &sweep, finding.FilterProd, "warn")
	return sweep
}

func TestAScopeSetsAsideTheGapOfAFindingItRemoved(t *testing.T) {
	sweep := sweepScoped(t, devCryptoRepo("app"))
	if code := sweepExit(sweep, threshold{severity: finding.SevCritical}); code != exitClear {
		t.Fatalf("exit = %d, want %d: the only gap is about a dev-only finding (gaps %v)",
			code, exitClear, sweep.AllGaps())
	}
	body, _ := json.Marshal(sweep)
	var got struct {
		Complete   bool          `json:"complete"`
		OutOfScope []finding.Gap `json:"out_of_scope_gaps"`
	}
	json.Unmarshal(body, &got)
	if !got.Complete || len(got.OutOfScope) != 1 || got.OutOfScope[0].Kind != finding.GapSeverity {
		t.Fatalf("json = %s, want the severity gap under out_of_scope_gaps", body)
	}
}

func TestAScopedGapStandsWhileAFindingInScopeHoldsIt(t *testing.T) {
	sweep := sweepScoped(t, devCryptoRepo("dev"), cryptoRepo("prod"))
	if code := sweepExit(sweep, threshold{severity: finding.SevCritical}); code != exitIncomplete {
		t.Fatalf("exit = %d, want %d: a prod repo still holds the unrated finding", code, exitIncomplete)
	}
	if len(sweep.OutOfScope) != 0 {
		t.Fatalf("out of scope = %v, want nothing set aside", sweep.OutOfScope)
	}
}

func TestAScopedReportSetsAsideOnlyTheGapsOfRemovedFindings(t *testing.T) {
	r := devCryptoRepo("app")
	resolve(context.Background(), fakeOSV(t, serveUnrated), r.pkgs, &r.report)
	scanGap := finding.Gap{Kind: finding.GapUpstream, Subject: "golang.org/x/crypto", Detail: "query failed"}
	r.report.Gaps = append(r.report.Gaps, scanGap)
	narrow(&r.report, finding.FilterProd, false)
	if len(r.report.Gaps) != 1 || r.report.Gaps[0] != scanGap {
		t.Fatalf("gaps = %v, want only the gap about the scan", r.report.Gaps)
	}
	if len(r.report.OutOfScope) != 1 || r.report.OutOfScope[0].Kind != finding.GapSeverity {
		t.Fatalf("out of scope = %v, want the dev-only finding's severity gap", r.report.OutOfScope)
	}
	body, _ := json.Marshal(r.report)
	var got struct {
		OutOfScope []finding.Gap `json:"out_of_scope_gaps"`
	}
	if json.Unmarshal(body, &got); len(got.OutOfScope) != 1 {
		t.Fatalf("json = %s, want out_of_scope_gaps", body)
	}
}
