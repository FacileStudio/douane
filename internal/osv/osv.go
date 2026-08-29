package osv

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/httpx"
)

const (
	batchURL  = "https://api.osv.dev/v1/querybatch"
	vulnURL   = "https://api.osv.dev/v1/vulns/"
	batchSize = 500
	workers   = 8
	userAgent = "douane (+https://github.com/FacileStudio/douane)"
)

// Client queries the OSV.dev database. The zero value is not usable; call New.
type Client struct {
	http   *httpx.Client
	base   string
	vuln   string
	absent map[string]bool
}

// Absent reports the ids douane asked OSV for and was told do not exist. It is
// the difference between "we never looked" and "it is not there", which is the
// only basis on which an identifier may be refused the primary slot.
func (c *Client) Absent() map[string]bool { return c.absent }

// New returns a Client pointed at the public OSV.dev API.
func New() *Client {
	return &Client{
		http: httpx.New(userAgent),
		base: batchURL,
		vuln: vulnURL,
	}
}

// Query returns, for each package, the ids of the vulnerabilities affecting it.
// The batch endpoint returns ids only, so details must be fetched separately.
//
// A chunk that fails costs its own packages and nothing else: the ids that did
// resolve come back alongside a gap naming the packages that did not, because
// discarding 500 answered packages over one refused request is how a scan
// reports clean on no evidence at all.
func (c *Client) Query(ctx context.Context, pkgs []finding.Package) ([][]string, []finding.Gap, error) {
	ids := make([][]string, len(pkgs))
	var gaps []finding.Gap
	var errs []error
	for start := 0; start < len(pkgs); start += batchSize {
		chunk := pkgs[start:min(start+batchSize, len(pkgs))]
		out, pageGaps, err := c.queryChunk(ctx, chunk)
		gaps = append(gaps, pageGaps...)
		if err != nil {
			errs = append(errs, err)
			gaps = append(gaps, finding.Gap{
				Kind:    finding.GapUpstream,
				Subject: chunkSubject(chunk),
				Detail:  err.Error(),
			})
			continue
		}
		collectIDs(ids, start, out)
	}
	return ids, gaps, errors.Join(errs...)
}

func collectIDs(ids [][]string, start int, out batchResponse) {
	for i, r := range out.Results {
		for _, v := range r.Vulns {
			ids[start+i] = append(ids[start+i], v.ID)
		}
	}
}

// chunkSubject names a failed chunk by its packages. A gap a reader cannot act
// on is barely better than no gap, and "500 packages" is not actionable.
func chunkSubject(pkgs []finding.Package) string {
	shown := min(3, len(pkgs))
	names := make([]string, 0, shown+1)
	for _, p := range pkgs[:shown] {
		names = append(names, p.Name)
	}
	if len(pkgs) > shown {
		names = append(names, fmt.Sprintf("+%d more", len(pkgs)-shown))
	}
	return strings.Join(names, ", ")
}
