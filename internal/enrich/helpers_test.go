package enrich

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/httpx"
)

// enrFastClient keeps the retry ladder out of the test clock. A test that
// serves a 500 is testing degradation, not backoff.
func enrFastClient() *httpx.Client {
	return httpx.New("douane/test").WithBackoff(time.Millisecond, 2*time.Millisecond)
}

func enrEnricher(t *testing.T, kev, epss http.HandlerFunc) *Enricher {
	t.Helper()
	ks, es := httptest.NewServer(kev), httptest.NewServer(epss)
	t.Cleanup(ks.Close)
	t.Cleanup(es.Close)
	e := New()
	e.http, e.kevURL, e.epssURL = enrFastClient(), ks.URL, es.URL
	return e
}

func enrKEV() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, kevBody) }
}

// enrFIRST answers the way api.first.org was measured to answer on
// 2026-08-23: a cve parameter over 2000 characters yields status OK with an
// empty array and a total of 0, and the array is cut to the page limit, which
// defaults to 100 however many ids were asked about.
func enrFIRST(hits *int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		*hits++
		q := r.URL.Query()
		matched := strings.Split(q.Get("cve"), ",")
		if len(q.Get("cve")) > epssJoinLimit {
			matched = nil
		}
		rows := make([]string, 0, len(matched))
		for _, id := range matched[:min(len(matched), enrPage(q.Get("limit")))] {
			rows = append(rows, fmt.Sprintf(`{"cve":%q,"epss":"0.5"}`, id))
		}
		fmt.Fprintf(w, `{"status":"OK","total":%d,"data":[%s]}`, len(matched), strings.Join(rows, ","))
	}
}

func enrPage(limit string) int {
	if n, err := strconv.Atoi(limit); err == nil && n > 0 {
		return n
	}
	return 100
}

func enrGapAbout(gaps []finding.Gap, text string) bool {
	for _, g := range gaps {
		if strings.Contains(g.String(), text) {
			return true
		}
	}
	return false
}
