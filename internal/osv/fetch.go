package osv

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"sync"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/httpx"
)

type fetchResult struct {
	id   string
	vuln Vuln
	err  error
}

// Fetch retrieves full records for the given ids, concurrently and
// deduplicated, then resolves each record's severity across its alias closure.
// A partial failure returns the records that did arrive alongside a gap per id
// that did not, and the joined error.
func (c *Client) Fetch(ctx context.Context, ids []string) (map[string]Vuln, []finding.Gap, error) {
	want := uniqueSorted(ids)
	out, failed := c.fetchSet(ctx, want)

	var gaps []finding.Gap
	var errs []error
	for _, id := range want {
		err, ok := failed[id]
		if !ok {
			continue
		}
		errs = append(errs, err)
		gaps = append(gaps, finding.Gap{
			Kind:    finding.GapUnresolved,
			Subject: id,
			Detail:  err.Error(),
		})
	}
	gaps = append(gaps, c.hydrate(ctx, out, want)...)
	return out, gaps, errors.Join(errs...)
}

// fetchSet splits a set of ids into the records that arrived and the errors
// that did not. A withdrawn record is neither: it is dropped here, at the one
// choke point every fetch passes through, so a retracted advisory can neither
// become a finding nor lend its severity to a closure. Dropping it later, at
// render time, would be too late: by then it has already keyed the store's
// history and moved the exit code.
func (c *Client) fetchSet(ctx context.Context, ids []string) (map[string]Vuln, map[string]error) {
	out := make(map[string]Vuln, len(ids))
	failed := map[string]error{}
	for r := range c.fetchAll(ctx, ids) {
		switch {
		case r.err != nil:
			failed[r.id] = r.err
			c.noteAbsent(r.id, r.err)
		case r.vuln.Withdrawn == "":
			out[r.id] = r.vuln
		}
	}
	return out, failed
}

// noteAbsent records an id OSV answered 404 for. Only a 404 counts: a timeout
// or a 500 means douane could not tell, and treating "could not tell" as "does
// not exist" is how a transient outage would quietly rename findings.
func (c *Client) noteAbsent(id string, err error) {
	var se *httpx.StatusError
	if !errors.As(err, &se) || se.Code != http.StatusNotFound {
		return
	}
	if c.absent == nil {
		c.absent = map[string]bool{}
	}
	c.absent[id] = true
}

// fetchAll runs the fetches over a fixed pool. The workers deliberately do not
// return early on a cancelled context: a worker that exits leaves its ids with
// neither a record nor an error, which is the one outcome douane cannot
// represent. Cancelled fetches fail fast on their own and each one is reported.
func (c *Client) fetchAll(ctx context.Context, ids []string) <-chan fetchResult {
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
		for _, id := range ids {
			jobs <- id
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	return results
}

// fetchOne reads one record. The id is escaped because half of them now come
// from the alias lists of other records rather than from douane's own query.
func (c *Client) fetchOne(ctx context.Context, id string) (Vuln, error) {
	var v Vuln
	if err := c.http.JSON(ctx, http.MethodGet, c.vuln+url.PathEscape(id), nil, &v); err != nil {
		return Vuln{}, fmt.Errorf("osv vulns/%s: %w", id, err)
	}
	return v, nil
}

func uniqueSorted(ids []string) []string {
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return slices.Sorted(maps.Keys(set))
}
