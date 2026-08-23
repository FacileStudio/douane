package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
)

func osvRespond(w http.ResponseWriter, results ...batchResult) {
	_ = json.NewEncoder(w).Encode(batchResponse{Results: results})
}

func osvHit(ids ...string) batchResult {
	r := batchResult{}
	for _, id := range ids {
		r.Vulns = append(r.Vulns, vulnID{ID: id})
	}
	return r
}

// OSV answers every error with {"code":N,"message":"..."} and no results key,
// which unmarshals cleanly into an empty response. Decoding before checking the
// status is therefore indistinguishable from a clean scan.
func TestQueryRefusesAnErrorEnvelope(t *testing.T) {
	c := osvClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"code":8,"message":"rate limit exceeded"}`))
	})
	pkgs := osvPackages(2)
	ids, gaps, err := c.Query(context.Background(), pkgs)
	if err == nil {
		t.Fatal("a 429 must be an error, not two packages reported clean")
	}
	if len(gaps) != 1 || gaps[0].Kind != finding.GapUpstream {
		t.Fatalf("gaps = %v, want one upstream gap", gaps)
	}
	if !strings.Contains(gaps[0].Subject, "pkg0") {
		t.Fatalf("gap subject = %q, want the packages that went unanswered", gaps[0].Subject)
	}
	for i, list := range ids {
		if len(list) != 0 {
			t.Fatalf("ids[%d] = %v, want nothing attributed from a refused request", i, list)
		}
	}
}

// The results are 1:1 and in order with the queries, so a short response cannot
// be read positionally: every id after a missing result lands on the wrong
// package, and the packages past the end report clean.
func TestQueryRejectsAShortResponse(t *testing.T) {
	c := osvClient(t, func(w http.ResponseWriter, r *http.Request) {
		osvRespond(w, osvHit("CVE-2026-1"))
	})
	ids, gaps, err := c.Query(context.Background(), osvPackages(3))
	if err == nil {
		t.Fatal("1 result for 3 queries must be an error, not a partial success")
	}
	if len(gaps) != 1 || gaps[0].Kind != finding.GapUpstream {
		t.Fatalf("gaps = %v, want one upstream gap", gaps)
	}
	for i, list := range ids {
		if len(list) != 0 {
			t.Fatalf("ids[%d] = %v, want nothing attributed from a response of the wrong length", i, list)
		}
	}
}

// A package with no vulnerabilities comes back as the empty object, which is
// normal and must stay normal.
func TestQueryAcceptsEmptyResults(t *testing.T) {
	c := osvClient(t, func(w http.ResponseWriter, r *http.Request) {
		osvRespond(w, osvHit("CVE-2026-1"), batchResult{}, osvHit("CVE-2026-2", "GHSA-x"))
	})
	ids, gaps, err := c.Query(context.Background(), osvPackages(3))
	if err != nil || len(gaps) != 0 {
		t.Fatalf("err = %v, gaps = %v, want a clean run", err, gaps)
	}
	if len(ids[0]) != 1 || len(ids[1]) != 0 || len(ids[2]) != 2 {
		t.Fatalf("ids = %v, want one, none and two", ids)
	}
}

func TestQueryKeepsTheChunksThatSucceeded(t *testing.T) {
	var calls atomic.Int32
	c := osvClient(t, func(w http.ResponseWriter, r *http.Request) {
		queries := osvQueries(t, r)
		if calls.Add(1) > 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"code":13,"message":"internal"}`))
			return
		}
		results := make([]batchResult, len(queries))
		results[0] = osvHit("CVE-2026-1")
		osvRespond(w, results...)
	})
	ids, gaps, err := c.Query(context.Background(), osvPackages(batchSize+1))
	if err == nil {
		t.Fatal("the failed chunk must still be an error")
	}
	if len(ids[0]) != 1 || ids[0][0] != "CVE-2026-1" {
		t.Fatalf("ids[0] = %v, want the ids the first chunk did resolve", ids[0])
	}
	if len(gaps) != 1 || !strings.Contains(gaps[0].Subject, "pkg500") {
		t.Fatalf("gaps = %v, want one gap naming the chunk that failed", gaps)
	}
}

// OSV pages per result, and the follow-up carries only the queries still
// paging, so the position in the original chunk shifts every round.
func TestQueryFollowsPageTokens(t *testing.T) {
	var calls atomic.Int32
	c := osvClient(t, func(w http.ResponseWriter, r *http.Request) {
		queries := osvQueries(t, r)
		if calls.Add(1) == 1 {
			first := osvHit("CVE-2026-1")
			first.NextPageToken = "page2"
			osvRespond(w, batchResult{}, first)
			return
		}
		if len(queries) != 1 || queries[0].PageToken != "page2" || queries[0].Package.Name != "pkg1" {
			t.Errorf("follow-up = %+v, want only the query that paged, carrying its token", queries)
		}
		osvRespond(w, osvHit("CVE-2026-2"))
	})
	ids, gaps, err := c.Query(context.Background(), osvPackages(2))
	if err != nil || len(gaps) != 0 {
		t.Fatalf("err = %v, gaps = %v, want a clean run", err, gaps)
	}
	if got := strings.Join(ids[1], ","); got != "CVE-2026-1,CVE-2026-2" {
		t.Fatalf("ids[1] = %v, want both pages", ids[1])
	}
}

func TestQueryReportsAPageItCouldNotFollow(t *testing.T) {
	c := osvClient(t, func(w http.ResponseWriter, r *http.Request) {
		queries := osvQueries(t, r)
		results := make([]batchResult, len(queries))
		results[0] = osvHit("CVE-2026-1")
		results[0].NextPageToken = "more"
		osvRespond(w, results...)
	})
	ids, gaps, err := c.Query(context.Background(), osvPackages(1))
	if err != nil {
		t.Fatalf("err = %v, want the ids that did arrive", err)
	}
	if len(ids[0]) == 0 {
		t.Fatal("the pages that did arrive must survive the truncation gap")
	}
	if len(gaps) != 1 || gaps[0].Kind != finding.GapUpstream || !strings.Contains(gaps[0].Detail, "truncated") {
		t.Fatalf("gaps = %v, want a truncation gap — a cut-short list must not be silent", gaps)
	}
}
