package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/osv"
	"github.com/FacileStudio/douane/internal/output"
)

func fakeOSV(t *testing.T, h http.HandlerFunc) *osv.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return osv.NewAt(srv.URL+"/v1/querybatch", srv.URL+"/v1/vulns/").WithAttempts(1)
}

func repoWith(name string, pkgs ...string) *repoScan {
	r := &repoScan{report: output.Report{Name: name, New: map[string]bool{}}}
	for _, p := range pkgs {
		r.pkgs = append(r.pkgs, finding.Package{Name: p, Ecosystem: "npm", Version: "1.0.0", Source: "package-lock.json"})
	}
	return r
}

func TestAFailedQueryMarksEveryRepoWithPackagesIncomplete(t *testing.T) {
	client := fakeOSV(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusBadRequest)
	})
	a, b, empty := repoWith("a", "left-pad"), repoWith("b", "hono"), repoWith("empty")
	var sweep output.Sweep

	resolveFleet(context.Background(), client, []*repoScan{a, b, empty}, &sweep)

	for _, r := range []*repoScan{a, b} {
		if r.report.Complete() || len(r.report.Findings) != 0 {
			t.Fatalf("repo %s: complete=%v findings=%d — an outage read as a clean repository",
				r.report.Name, r.report.Complete(), len(r.report.Findings))
		}
	}
	if !empty.report.Complete() {
		t.Fatal("a repository with no packages asked OSV nothing and must stay complete")
	}
	if len(sweep.Gaps) == 0 {
		t.Fatal("the fleet lost its own gap")
	}
}

func TestAFailedAdvisoryFetchMarksOnlyTheRepoThatAskedForIt(t *testing.T) {
	client := fakeOSV(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/querybatch") {
			var req struct {
				Queries []struct{ Package struct{ Name string } }
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			var results []map[string]any
			for _, q := range req.Queries {
				if q.Package.Name == "left-pad" {
					results = append(results, map[string]any{"vulns": []map[string]string{{"id": "GHSA-gone-0000-0000"}}})
					continue
				}
				results = append(results, map[string]any{})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
			return
		}
		http.Error(w, "unavailable", http.StatusBadRequest)
	})
	a, b := repoWith("a", "left-pad"), repoWith("b", "hono")
	var sweep output.Sweep

	resolveFleet(context.Background(), client, []*repoScan{a, b}, &sweep)

	if a.report.Complete() {
		t.Fatal("repo a asked for the advisory that never arrived but reads complete")
	}
	if !b.report.Complete() {
		t.Fatalf("repo b never asked for it but carries %v", b.report.Gaps)
	}
}

func TestAFleetGapInheritedByReposIsCountedOnce(t *testing.T) {
	gap := finding.Gap{Kind: finding.GapUpstream, Subject: "left-pad", Detail: "down"}
	sweep := output.Sweep{Gaps: []finding.Gap{gap}, Repos: []output.Report{{Gaps: []finding.Gap{gap}}, {Gaps: []finding.Gap{gap}}}}

	if got := sweep.AllGaps(); len(got) != 1 {
		t.Fatalf("AllGaps = %d, want 1", len(got))
	}
}
