package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func (e *Enricher) kev(ctx context.Context) (map[string]bool, error) {
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
	var doc struct {
		Vulnerabilities []struct {
			CveID                      string `json:"cveID"`
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("kev decode: %w", err)
	}
	out := make(map[string]bool, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		out[v.CveID] = strings.EqualFold(v.KnownRansomwareCampaignUse, "Known")
	}
	return out, nil
}

func (e *Enricher) epss(ctx context.Context, cves []string) (map[string]float64, error) {
	out := map[string]float64{}
	for start := 0; start < len(cves); start += epssPerCall {
		end := min(start+epssPerCall, len(cves))
		if err := e.epssChunk(ctx, cves[start:end], out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

type epssResponse struct {
	Data []struct {
		CVE  string `json:"cve"`
		EPSS string `json:"epss"`
	} `json:"data"`
}

func (e *Enricher) epssChunk(ctx context.Context, cves []string, out map[string]float64) error {
	url := e.epssURL + "?cve=" + strings.Join(cves, ",")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := e.http.Do(req)
	if err != nil {
		return fmt.Errorf("epss: %w", err)
	}
	defer resp.Body.Close()

	var doc epssResponse
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("epss decode: %w", err)
	}
	for _, d := range doc.Data {
		if v, perr := strconv.ParseFloat(d.EPSS, 64); perr == nil {
			out[d.CVE] = v
		}
	}
	return nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
