package osv

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/httpx"
)

// osvClient points a Client at a test server so both OSV paths can be driven
// without touching api.osv.dev. One attempt, because these tests assert what a
// failure does and not how long it waits.
func osvClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &Client{
		http: httpx.New("douane/test").WithAttempts(1),
		base: srv.URL + "/v1/querybatch",
		vuln: srv.URL + "/v1/vulns/",
	}
}

// osvVulnServer serves a fixed set of records from the detail endpoint and
// counts the requests, so a test can assert what the closure pass fetched.
func osvVulnServer(t *testing.T, records map[string]Vuln) (*Client, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	c := osvClient(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		v, ok := records[strings.TrimPrefix(r.URL.Path, "/v1/vulns/")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":5,"message":"Bug not found."}`))
			return
		}
		_ = json.NewEncoder(w).Encode(v)
	})
	return c, &hits
}

// osvQueries decodes a batch request, which is how a test server answers with
// the one-result-per-query shape OSV guarantees.
func osvQueries(t *testing.T, r *http.Request) []queryEntry {
	t.Helper()
	var in struct {
		Queries []queryEntry `json:"queries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		t.Fatalf("decoding the batch request: %v", err)
	}
	return in.Queries
}

func osvPackages(n int) []finding.Package {
	pkgs := make([]finding.Package, n)
	for i := range pkgs {
		pkgs[i] = finding.Package{
			Name:      "pkg" + strconv.Itoa(i),
			Ecosystem: "npm",
			Version:   "1.0.0",
		}
	}
	return pkgs
}

// osvAffected builds one affected entry, which keeps the advisory literals in
// the tests flat enough to read.
func osvAffected(name, ecosystem, kind string, events ...Event) Affected {
	r := Range{Type: kind, Events: events}
	return Affected{Package: PackageRef{Name: name, Ecosystem: ecosystem}, Ranges: []Range{r}}
}

// osvScore builds one CVSS scoring.
func osvScore(kind, vector string) []SeverityScore {
	return []SeverityScore{{Type: kind, Score: vector}}
}
