package enrich

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/FacileStudio/douane/internal/finding"
)

const kevBody = `{"vulnerabilities":[{"cveID":"CVE-2026-0001","knownRansomwareCampaignUse":"Known"}]}`
const epssBody = `{"data":[{"cve":"CVE-2026-0001","epss":"0.5"}]}`

type fakeCache struct {
	feed   map[string][]byte
	feedAt map[string]time.Time
	epss   map[string]float64
	epssAt map[string]time.Time
}

func newFakeCache() *fakeCache {
	return &fakeCache{
		feed:   map[string][]byte{},
		feedAt: map[string]time.Time{},
		epss:   map[string]float64{},
		epssAt: map[string]time.Time{},
	}
}

func (c *fakeCache) Feed(name string) ([]byte, time.Time, error) {
	return c.feed[name], c.feedAt[name], nil
}

func (c *fakeCache) SaveFeed(name string, payload []byte) error {
	c.feed[name], c.feedAt[name] = payload, time.Now()
	return nil
}

func (c *fakeCache) EPSS(since time.Time) (map[string]float64, error) {
	out := map[string]float64{}
	for cve, score := range c.epss {
		if !c.epssAt[cve].Before(since) {
			out[cve] = score
		}
	}
	return out, nil
}

func (c *fakeCache) SaveEPSS(scores map[string]float64) error {
	for cve, score := range scores {
		c.epss[cve], c.epssAt[cve] = score, time.Now()
	}
	return nil
}

type counters struct{ kev, epss int }

func testEnricher(t *testing.T, c Cache, hits *counters, status int) *Enricher {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/kev", func(w http.ResponseWriter, r *http.Request) {
		hits.kev++
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		io.WriteString(w, kevBody)
	})
	mux.HandleFunc("/epss", func(w http.ResponseWriter, r *http.Request) {
		hits.epss++
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		io.WriteString(w, epssBody)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	e := New().WithCache(c)
	e.http, e.kevURL, e.epssURL = enrFastClient(), srv.URL+"/kev", srv.URL+"/epss"
	return e
}

func fixtures() []finding.Finding {
	return []finding.Finding{
		{ID: "CVE-2026-0001", Package: "a"},
		{ID: "CVE-2026-0002", Package: "b"},
	}
}

func TestSecondRunTouchesNoFeed(t *testing.T) {
	cache, hits := newFakeCache(), &counters{}
	e := testEnricher(t, cache, hits, http.StatusOK)

	first := fixtures()
	if res := e.Apply(context.Background(), first); !res.KEVOK || !res.EPSSOK {
		t.Fatalf("first run: kev=%v epss=%v", res.KEVErr, res.EPSSErr)
	}
	before := *hits

	second := fixtures()
	res := e.Apply(context.Background(), second)
	if *hits != before {
		t.Fatalf("second run made requests: kev %d->%d, epss %d->%d",
			before.kev, hits.kev, before.epss, hits.epss)
	}
	if !res.KEVOK || !res.EPSSOK || res.KEVStale {
		t.Fatalf("second run degraded: %+v", res)
	}
	if !second[0].Exploit.KEV || !second[0].Exploit.Ransomware {
		t.Fatal("cached KEV catalogue did not flag CVE-2026-0001")
	}
	if second[0].Exploit.EPSS != 0.5 || !second[0].Exploit.EPSSKnown {
		t.Fatalf("cached EPSS score = %v, want 0.5", second[0].Exploit.EPSS)
	}
	if second[1].Exploit.EPSSKnown {
		t.Fatal("CVE-2026-0002 has no EPSS score and must not read as known")
	}
}

func TestUnscoredCVEIsNotRequeried(t *testing.T) {
	cache, hits := newFakeCache(), &counters{}
	e := testEnricher(t, cache, hits, http.StatusOK)
	e.Apply(context.Background(), fixtures())

	if got := cache.epss["CVE-2026-0002"]; got != scoreUnknown {
		t.Fatalf("cached score for an unscored CVE = %v, want %v", got, scoreUnknown)
	}
	e.Apply(context.Background(), fixtures())
	if hits.epss != 1 {
		t.Fatalf("epss requests = %d, want 1 — the unscored CVE was queried again", hits.epss)
	}
}

func TestStaleCacheSurvivesADeadFeed(t *testing.T) {
	cache, hits := newFakeCache(), &counters{}
	cache.feed[kevFeed] = []byte(kevBody)
	cache.feedAt[kevFeed] = time.Now().Add(-48 * time.Hour)
	cache.epss["CVE-2026-0001"] = 0.5
	cache.epssAt["CVE-2026-0001"] = time.Now()

	e := testEnricher(t, cache, hits, http.StatusInternalServerError)
	fs := fixtures()
	res := e.Apply(context.Background(), fs)

	if !res.KEVOK || !res.KEVStale {
		t.Fatalf("want a stale but usable catalogue, got %+v", res)
	}
	if res.KEVAge < 47*time.Hour {
		t.Fatalf("KEVAge = %v, want ~48h", res.KEVAge)
	}
	if !fs[0].Exploit.KEV {
		t.Fatal("stale catalogue was not applied")
	}
	if !res.EPSSOK || !res.EPSSStale {
		t.Fatalf("want EPSS degraded to cache, got %+v", res)
	}
	if fs[0].Exploit.EPSS != 0.5 {
		t.Fatalf("cached EPSS score lost: %v", fs[0].Exploit.EPSS)
	}
}

func TestRefreshStillFallsBackToTheCache(t *testing.T) {
	cache, hits := newFakeCache(), &counters{}
	cache.feed[kevFeed] = []byte(kevBody)
	cache.feedAt[kevFeed] = time.Now()
	cache.epss["CVE-2026-0001"] = 0.5
	cache.epssAt["CVE-2026-0001"] = time.Now()

	e := testEnricher(t, cache, hits, http.StatusInternalServerError).WithRefresh(true)
	fs := fixtures()
	res := e.Apply(context.Background(), fs)

	if !res.KEVOK || !res.EPSSOK {
		t.Fatalf("-refresh with a dead feed dropped an axis it had cached: %+v", res)
	}
	if !fs[0].Exploit.KEV {
		t.Fatal("cached catalogue was not applied under -refresh")
	}
	if fs[0].Exploit.EPSS != 0.5 {
		t.Fatalf("cached EPSS score = %v, want 0.5 — -refresh must prefer fresh, not discard the cache",
			fs[0].Exploit.EPSS)
	}
}

func TestEmptyCatalogueIsRefused(t *testing.T) {
	cache, hits := newFakeCache(), &counters{}
	e := testEnricher(t, cache, hits, http.StatusOK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"vulnerabilities":[]}`)
	}))
	t.Cleanup(srv.Close)
	e.kevURL = srv.URL

	res := e.Apply(context.Background(), fixtures())
	if res.KEVOK {
		t.Fatal("an empty catalogue must not count as a working feed")
	}
	if _, ok := cache.feed[kevFeed]; ok {
		t.Fatal("an empty catalogue must never be cached")
	}
}
