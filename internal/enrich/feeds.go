package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const feedSizeLimit = 32 << 20

// kevCatalog resolves the known-exploited catalogue, preferring a fresh cache,
// then the network, then a cache past its TTL. Only the last case is reported
// as stale: an answer from an expired cache is still worth having, but the
// caller has to be able to say where it came from.
func (e *Enricher) kevCatalog(ctx context.Context, res *Result) (map[string]bool, error) {
	if payload, at, ok := e.cachedKEV(); ok && !e.refresh && time.Since(at) < feedTTL {
		if catalog, err := decodeKEV(payload); err == nil {
			res.KEVAge = time.Since(at)
			return catalog, nil
		}
	}
	raw, err := e.fetchKEV(ctx)
	if err == nil {
		catalog, derr := decodeKEV(raw)
		if derr == nil {
			res.CacheErr = e.saveKEV(raw)
			return catalog, nil
		}
		err = derr
	}
	return e.staleKEV(res, err)
}

func (e *Enricher) staleKEV(res *Result, cause error) (map[string]bool, error) {
	payload, at, ok := e.cachedKEV()
	if !ok {
		return nil, cause
	}
	catalog, err := decodeKEV(payload)
	if err != nil {
		return nil, cause
	}
	res.KEVStale, res.KEVAge = true, time.Since(at)
	return catalog, nil
}

func (e *Enricher) cachedKEV() ([]byte, time.Time, bool) {
	if e.cache == nil {
		return nil, time.Time{}, false
	}
	payload, at, err := e.cache.Feed(kevFeed)
	if err != nil || len(payload) == 0 {
		return nil, time.Time{}, false
	}
	return payload, at, true
}

func (e *Enricher) saveKEV(payload []byte) error {
	if e.cache == nil {
		return nil
	}
	return e.cache.SaveFeed(kevFeed, payload)
}

func (e *Enricher) fetchKEV(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.kevURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := e.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kev: status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, feedSizeLimit))
}

// decodeKEV parses the catalogue and refuses an empty one. An empty catalogue
// is indistinguishable from "nothing is exploited", which would silence the
// top prioritiser for a whole TTL if it were ever cached.
func decodeKEV(payload []byte) (map[string]bool, error) {
	var doc struct {
		Vulnerabilities []struct {
			CveID                      string `json:"cveID"`
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("kev decode: %w", err)
	}
	if len(doc.Vulnerabilities) == 0 {
		return nil, errors.New("kev: catalogue is empty")
	}
	out := make(map[string]bool, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		out[v.CveID] = strings.EqualFold(v.KnownRansomwareCampaignUse, "Known")
	}
	return out, nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
