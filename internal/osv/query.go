package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

// maxPages bounds how far one chunk is followed through next_page_token. OSV
// pages a result past 1000 vulnerabilities; a queryset that is still paging
// after this many rounds is reported as truncated rather than followed forever.
const maxPages = 10

type queryEntry struct {
	Package   PackageRef `json:"package"`
	Version   string     `json:"version"`
	PageToken string     `json:"page_token,omitempty"`
}

type vulnID struct {
	ID string `json:"id"`
}

type batchResult struct {
	Vulns         []vulnID `json:"vulns"`
	NextPageToken string   `json:"next_page_token,omitempty"`
}

type batchResponse struct {
	Results []batchResult `json:"results"`
}

// queryChunk runs one batch and returns its results, one per query. OSV
// guarantees the results are 1:1 and in order with the queries, so a response
// of a different length cannot be read positionally at all — every id after the
// first missing result would be attributed to the wrong package.
func (c *Client) queryChunk(ctx context.Context, chunk []finding.Package) (batchResponse, []finding.Gap, error) {
	queries := make([]queryEntry, len(chunk))
	for i, p := range chunk {
		queries[i] = queryEntry{
			Package: PackageRef{Name: p.Name, Ecosystem: p.Ecosystem},
			Version: p.Version,
		}
	}
	out, err := c.postQueries(ctx, queries)
	if err != nil {
		return out, nil, err
	}
	if len(out.Results) != len(chunk) {
		return out, nil, fmt.Errorf("osv querybatch: %d results for %d queries", len(out.Results), len(chunk))
	}
	return out, c.followPages(ctx, queries, out.Results), nil
}

func (c *Client) postQueries(ctx context.Context, queries []queryEntry) (batchResponse, error) {
	var out batchResponse
	body, err := json.Marshal(map[string]any{"queries": queries})
	if err != nil {
		return out, err
	}
	if err := c.http.JSON(ctx, http.MethodPost, c.base, body, &out); err != nil {
		return out, fmt.Errorf("osv querybatch: %w", err)
	}
	return out, nil
}

// followPages resolves the results that came back with a next_page_token. OSV
// pages per result and the follow-up carries only the queries still paging, so
// the position in the original chunk shifts every round and has to be carried
// alongside. A page that never arrives is a gap: the alternative is a package
// whose vulnerability list is silently cut short.
func (c *Client) followPages(ctx context.Context, queries []queryEntry, results []batchResult) []finding.Gap {
	pending := pendingPages(results)
	for round := 0; len(pending) > 0 && round < maxPages; round++ {
		out, err := c.postQueries(ctx, pageQueries(queries, results, pending))
		if err != nil {
			return []finding.Gap{pageGap(queries, pending, err.Error())}
		}
		if len(out.Results) != len(pending) {
			detail := fmt.Sprintf("page %d: %d results for %d queries", round+1, len(out.Results), len(pending))
			return []finding.Gap{pageGap(queries, pending, detail)}
		}
		mergePage(results, pending, out.Results)
		pending = pendingPages(results)
	}
	if len(pending) == 0 {
		return nil
	}
	return []finding.Gap{pageGap(queries, pending, fmt.Sprintf("still paging after %d pages", maxPages))}
}

func pageQueries(queries []queryEntry, results []batchResult, pending []int) []queryEntry {
	next := make([]queryEntry, len(pending))
	for i, at := range pending {
		next[i] = queries[at]
		next[i].PageToken = results[at].NextPageToken
	}
	return next
}

func mergePage(results []batchResult, pending []int, page []batchResult) {
	for i, at := range pending {
		results[at].Vulns = append(results[at].Vulns, page[i].Vulns...)
		results[at].NextPageToken = page[i].NextPageToken
	}
}

func pendingPages(results []batchResult) []int {
	var pending []int
	for i, r := range results {
		if r.NextPageToken != "" {
			pending = append(pending, i)
		}
	}
	return pending
}

func pageGap(queries []queryEntry, pending []int, detail string) finding.Gap {
	names := make([]string, 0, len(pending))
	for _, at := range pending {
		names = append(names, queries[at].Package.Name)
	}
	return finding.Gap{
		Kind:    finding.GapUpstream,
		Subject: strings.Join(names, ", "),
		Detail:  "truncated vulnerability list: " + detail,
	}
}
