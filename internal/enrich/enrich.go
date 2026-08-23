package enrich

import (
	"context"
	"time"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/httpx"
	"github.com/FacileStudio/douane/internal/version"
)

const (
	kevURL        = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
	epssURL       = "https://api.first.org/data/v1/epss"
	kevFeed       = "kev"
	epssFeed      = "epss"
	feedTTL       = 24 * time.Hour
	feedSizeLimit = 32 << 20
)

// scoreUnknown records that EPSS was asked about a CVE and had no score for it.
// Without it every unscored advisory is re-queried on every run, and a sweep
// over a warm cache still talks to the network.
const scoreUnknown = -1

// Cache keeps feed data between runs. KEV is one catalogue, so it is cached
// whole; EPSS answers per CVE, so it is cached per CVE and only the missing
// ones are ever fetched.
type Cache interface {
	Feed(name string) ([]byte, time.Time, error)
	SaveFeed(name string, payload []byte) error
	EPSS(since time.Time) (map[string]float64, error)
	SaveEPSS(scores map[string]float64) error
}

// Result reports which feeds answered. A feed being unreachable degrades the
// ranking, it never fails the sweep — but the caller must be able to say so,
// including when the answer came from a cache that is past its TTL, which is
// what Gaps carries into the exit code.
type Result struct {
	KEVOK     bool
	EPSSOK    bool
	KEVErr    error
	EPSSErr   error
	KEVAge    time.Duration
	KEVStale  bool
	EPSSStale bool
	CacheErr  error
	Gaps      []finding.Gap
}

// Enricher annotates findings with real-world exploitation signals.
type Enricher struct {
	http    *httpx.Client
	kevURL  string
	epssURL string
	cache   Cache
	refresh bool
}

// New returns an Enricher pointed at the public KEV and EPSS feeds.
func New() *Enricher {
	return &Enricher{
		http:    httpx.New(version.UserAgent()).WithMaxBody(feedSizeLimit),
		kevURL:  kevURL,
		epssURL: epssURL,
	}
}

// WithCache makes the Enricher read and write feed data through c. Pass a real
// cache or leave it unset — a nil pointer wrapped in the interface is not the
// same as no cache, and will panic on first use.
func (e *Enricher) WithCache(c Cache) *Enricher {
	e.cache = c
	return e
}

// WithRefresh forces a fetch even when the cached feeds are still fresh.
func (e *Enricher) WithRefresh(v bool) *Enricher {
	e.refresh = v
	return e
}

// Apply fills the exploitation signals of every finding in place. Neither feed
// aborts the other, and whatever either one could not answer leaves a gap
// behind: a KEV catalogue that never arrived must not read as "nothing here is
// exploited", which is what -fail kev was measuring before.
func (e *Enricher) Apply(ctx context.Context, fs []finding.Finding) Result {
	var res Result
	kev, err := e.kevCatalog(ctx, &res)
	if err != nil {
		res.KEVErr = err
	} else {
		res.KEVOK = true
		applyKEV(fs, kev)
	}

	cves, malformed := epssIDs(fs)
	scores, err := e.epssScores(ctx, cves, &res)
	if err != nil {
		res.EPSSErr = err
	} else {
		res.EPSSOK = true
		applyEPSS(fs, scores)
	}
	res.Gaps = enrGaps(&res, malformed)
	return res
}

func identifiers(f finding.Finding) []string {
	return append([]string{f.ID}, f.Aliases...)
}

func applyKEV(fs []finding.Finding, kev map[string]bool) {
	for i := range fs {
		for _, id := range identifiers(fs[i]) {
			ransomware, ok := kev[id]
			if !ok {
				continue
			}
			fs[i].Exploit.KEV = true
			fs[i].Exploit.Ransomware = ransomware
			break
		}
	}
}

func applyEPSS(fs []finding.Finding, scores map[string]float64) {
	for i := range fs {
		for _, id := range identifiers(fs[i]) {
			score, ok := scores[id]
			if !ok {
				continue
			}
			fs[i].Exploit.EPSS = score
			fs[i].Exploit.EPSSKnown = true
			break
		}
	}
}
