package enrich

import (
	"context"
	"time"
)

// epssScores returns a score per CVE, fetching only the ones the cache does
// not already hold. A failed fetch with a partial cache degrades to what is
// cached rather than dropping the axis entirely.
func (e *Enricher) epssScores(ctx context.Context, cves []string, res *Result) (map[string]float64, error) {
	cached := e.cachedEPSS()
	missing := missingCVEs(cves, cached)
	if len(missing) == 0 {
		return scored(cached), nil
	}
	fetched, err := e.epss(ctx, missing)
	if err != nil {
		return e.staleEPSS(res, cached, err)
	}
	if err := e.saveEPSS(missing, fetched); err != nil {
		res.CacheErr = err
	}
	for cve, score := range fetched {
		cached[cve] = score
	}
	return scored(cached), nil
}

// staleEPSS falls back to every score the cache holds, past its TTL and even
// when -refresh asked for a fetch: a flag meaning "prefer fresh" must not mean
// "lose what we have" the moment the feed is unreachable. KEV degrades the
// same way, and one flag must not mean two things.
func (e *Enricher) staleEPSS(res *Result, cached map[string]float64, cause error) (map[string]float64, error) {
	for cve, score := range e.everyCachedEPSS() {
		if _, ok := cached[cve]; !ok {
			cached[cve] = score
		}
	}
	if len(cached) == 0 {
		return nil, cause
	}
	res.EPSSStale = true
	return scored(cached), nil
}

// everyCachedEPSS returns the whole cache, ignoring both the TTL and -refresh.
// It is the fallback path only.
func (e *Enricher) everyCachedEPSS() map[string]float64 {
	if e.cache == nil {
		return nil
	}
	out, err := e.cache.EPSS(time.Time{})
	if err != nil {
		return nil
	}
	return out
}

func (e *Enricher) cachedEPSS() map[string]float64 {
	if e.cache == nil || e.refresh {
		return map[string]float64{}
	}
	out, err := e.cache.EPSS(time.Now().Add(-feedTTL))
	if err != nil || out == nil {
		return map[string]float64{}
	}
	return out
}

// saveEPSS records a score for every CVE that was asked about, including the
// ones EPSS has no score for.
func (e *Enricher) saveEPSS(asked []string, fetched map[string]float64) error {
	if e.cache == nil {
		return nil
	}
	out := make(map[string]float64, len(asked))
	for _, cve := range asked {
		score, ok := fetched[cve]
		if !ok {
			score = scoreUnknown
		}
		out[cve] = score
	}
	return e.cache.SaveEPSS(out)
}

func missingCVEs(cves []string, cached map[string]float64) []string {
	var out []string
	for _, cve := range cves {
		if _, ok := cached[cve]; !ok {
			out = append(out, cve)
		}
	}
	return out
}

// scored drops the CVEs EPSS has no score for, so a cached "no score" never
// reads as a score of zero.
func scored(all map[string]float64) map[string]float64 {
	out := make(map[string]float64, len(all))
	for cve, score := range all {
		if score >= 0 {
			out[cve] = score
		}
	}
	return out
}
