package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/FacileStudio/douane/internal/finding"
)

const (
	batchURL  = "https://api.osv.dev/v1/querybatch"
	vulnURL   = "https://api.osv.dev/v1/vulns/"
	batchSize = 500
	workers   = 8
)

// Client queries the OSV.dev database. The zero value is not usable; call New.
type Client struct {
	http *http.Client
	base string
	vuln string
}

// New returns a Client pointed at the public OSV.dev API.
func New() *Client {
	return &Client{
		http: &http.Client{Timeout: 30 * time.Second},
		base: batchURL,
		vuln: vulnURL,
	}
}

type queryEntry struct {
	Package PackageRef `json:"package"`
	Version string     `json:"version"`
}

type batchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// Query returns, for each package, the ids of the vulnerabilities affecting it.
// The batch endpoint returns ids only, so details must be fetched separately.
func (c *Client) Query(ctx context.Context, pkgs []finding.Package) ([][]string, error) {
	ids := make([][]string, len(pkgs))
	for start := 0; start < len(pkgs); start += batchSize {
		end := min(start+batchSize, len(pkgs))
		out, err := c.queryChunk(ctx, pkgs[start:end])
		if err != nil {
			return nil, err
		}
		collectIDs(ids, start, out)
	}
	return ids, nil
}

func collectIDs(ids [][]string, start int, out batchResponse) {
	for i, r := range out.Results {
		if start+i >= len(ids) {
			return
		}
		for _, v := range r.Vulns {
			ids[start+i] = append(ids[start+i], v.ID)
		}
	}
}

func (c *Client) queryChunk(ctx context.Context, chunk []finding.Package) (batchResponse, error) {
	var out batchResponse
	queries := make([]queryEntry, len(chunk))
	for i, p := range chunk {
		queries[i] = queryEntry{
			Package: PackageRef{Name: p.Name, Ecosystem: p.Ecosystem},
			Version: p.Version,
		}
	}
	body, err := json.Marshal(map[string]any{"queries": queries})
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base, bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return out, fmt.Errorf("osv querybatch: %w", err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, fmt.Errorf("osv querybatch decode: %w", err)
	}
	return out, nil
}

type fetchResult struct {
	id   string
	vuln Vuln
	err  error
}

// Fetch retrieves full records for the given ids, concurrently and deduplicated.
// A partial failure returns the records that did arrive alongside the error.
func (c *Client) Fetch(ctx context.Context, ids []string) (map[string]Vuln, error) {
	unique := map[string]bool{}
	for _, id := range ids {
		unique[id] = true
	}
	results := c.fetchAll(ctx, unique)

	out := make(map[string]Vuln, len(unique))
	var firstErr error
	for r := range results {
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		out[r.id] = r.vuln
	}
	return out, firstErr
}

func (c *Client) fetchAll(ctx context.Context, ids map[string]bool) <-chan fetchResult {
	jobs := make(chan string)
	results := make(chan fetchResult)

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				v, err := c.fetchOne(ctx, id)
				results <- fetchResult{id: id, vuln: v, err: err}
			}
		}()
	}
	go func() {
		for id := range ids {
			jobs <- id
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	return results
}

func (c *Client) fetchOne(ctx context.Context, id string) (Vuln, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.vuln+id, nil)
	if err != nil {
		return Vuln{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Vuln{}, fmt.Errorf("osv vulns/%s: %w", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Vuln{}, fmt.Errorf("osv vulns/%s: status %d", id, resp.StatusCode)
	}
	var v Vuln
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return Vuln{}, fmt.Errorf("osv vulns/%s decode: %w", id, err)
	}
	return v, nil
}
