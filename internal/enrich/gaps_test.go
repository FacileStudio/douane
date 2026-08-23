package enrich

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestDeadKEVFeedLeavesAGap(t *testing.T) {
	var hits int
	e := enrEnricher(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}, enrFIRST(&hits))

	fs := fixtures()
	res := e.Apply(context.Background(), fs)
	if res.KEVOK {
		t.Fatal("a 500 from the catalogue must not read as a working feed")
	}
	if fs[0].Exploit.KEV {
		t.Fatal("no catalogue means no KEV flag")
	}
	if !enrGapAbout(res.Gaps, kevFeed) {
		t.Fatalf("-fail kev would have measured nothing and passed, gaps: %v", res.Gaps)
	}
}

func TestStaleCatalogueLeavesAGap(t *testing.T) {
	var hits int
	cache := newFakeCache()
	cache.feed[kevFeed] = []byte(kevBody)
	cache.feedAt[kevFeed] = time.Now().Add(-48 * time.Hour)

	e := enrEnricher(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}, enrFIRST(&hits)).WithCache(cache)

	res := e.Apply(context.Background(), fixtures())
	if !res.KEVOK || !res.KEVStale {
		t.Fatalf("want the cached catalogue used and marked stale, got %+v", res)
	}
	if !enrGapAbout(res.Gaps, "48h") {
		t.Fatalf("a catalogue two days old must say so, gaps: %v", res.Gaps)
	}
}

func TestDeadEPSSFeedLeavesAGap(t *testing.T) {
	e := enrEnricher(t, enrKEV(), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	res := e.Apply(context.Background(), fixtures())
	if res.EPSSOK {
		t.Fatal("a 503 must not read as a working feed")
	}
	if !enrGapAbout(res.Gaps, epssFeed) {
		t.Fatalf("a dead EPSS feed must leave a gap, got %v", res.Gaps)
	}
}

func TestHealthyRunLeavesNoGap(t *testing.T) {
	var hits int
	e := enrEnricher(t, enrKEV(), enrFIRST(&hits))

	res := e.Apply(context.Background(), fixtures())
	if !res.KEVOK || !res.EPSSOK {
		t.Fatalf("both feeds answered: %+v", res)
	}
	if len(res.Gaps) != 0 {
		t.Fatalf("a complete run must be gapless, got %v", res.Gaps)
	}
}
