package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// epssSnippet bounds what an undecodable body contributes to an error.
const epssSnippet = 200

// epss fetches a score for every CVE in cves. The API is asked one batch at a
// time: FIRST asks callers to avoid concurrent requests, and a sequential
// walk over a handful of batches is nowhere near the documented 1000 requests
// a minute.
func (e *Enricher) epss(ctx context.Context, cves []string) (map[string]float64, error) {
	out := map[string]float64{}
	for _, batch := range epssBatches(cves) {
		if err := e.epssChunk(ctx, batch, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// epssEnvelope is the response wrapper. Data stays raw because its type is
// not stable: on HTTP 422 the array of scores becomes the object
// {"error":["listNoResults"]}, which decodes into a slice only as an error.
type epssEnvelope struct {
	Status string          `json:"status"`
	Total  int             `json:"total"`
	Data   json.RawMessage `json:"data"`
}

type epssRow struct {
	CVE  string `json:"cve"`
	EPSS string `json:"epss"`
}

// epssChunk asks about one batch of CVEs. The ids go through url.Values so
// that a malformed one cannot become a second parameter, and limit is sent
// explicitly because the API pages at 100 by default and announces it only in
// the envelope: 120 ids answer "total":120 with 100 rows in the array.
func (e *Enricher) epssChunk(ctx context.Context, cves []string, out map[string]float64) error {
	q := url.Values{"cve": {strings.Join(cves, ",")}, "limit": {strconv.Itoa(len(cves))}}
	var doc epssEnvelope
	if err := e.http.JSON(ctx, http.MethodGet, e.epssURL+"?"+q.Encode(), nil, &doc); err != nil {
		return fmt.Errorf("epss: %w", err)
	}
	rows, err := epssRows(doc)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if v, perr := strconv.ParseFloat(r.EPSS, 64); perr == nil {
			out[r.CVE] = v
		}
	}
	return nil
}

// epssRows reads the scores out of an envelope and refuses the two answers
// that carry none while decoding cleanly: the error object the API
// substitutes for the array, and a page shorter than the total it reports.
// Both would otherwise land as "no CVE here is scored".
func epssRows(doc epssEnvelope) ([]epssRow, error) {
	if doc.Status != "" && doc.Status != "OK" {
		return nil, fmt.Errorf("epss: status %q", doc.Status)
	}
	var rows []epssRow
	if len(doc.Data) > 0 {
		if err := json.Unmarshal(doc.Data, &rows); err != nil {
			return nil, fmt.Errorf("epss decode: %w: %s", err, epssCut(doc.Data))
		}
	}
	if doc.Total > len(rows) {
		return nil, fmt.Errorf("epss: answered %d of the %d scores it reported", len(rows), doc.Total)
	}
	return rows, nil
}

func epssCut(b []byte) string {
	if len(b) > epssSnippet {
		return string(b[:epssSnippet]) + "..."
	}
	return string(b)
}
