package enrich

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
)

// enrLongIDs builds findings whose CVE ids are 21 characters, which is what a
// seven-digit sequence number already costs. A hundred of them join into 2199
// characters, so a batch counted in ids rather than characters asks a question
// the API answers with an empty array.
func enrLongIDs(n int) []finding.Finding {
	fs := make([]finding.Finding, 0, n)
	for i := range n {
		fs = append(fs, finding.Finding{ID: fmt.Sprintf("CVE-2026-%012d", i), Package: "p"})
	}
	return fs
}

func TestLongIDsAreBatchedByLengthNotCount(t *testing.T) {
	var hits int
	e := enrEnricher(t, enrKEV(), enrFIRST(&hits))
	fs := enrLongIDs(120)

	res := e.Apply(context.Background(), fs)
	if !res.EPSSOK {
		t.Fatalf("EPSS dropped: %v", res.EPSSErr)
	}
	for i := range fs {
		if !fs[i].Exploit.EPSSKnown {
			t.Fatalf("%s came back unscored after %d request(s): over the %d-character cap, silently refused",
				fs[i].ID, hits, epssJoinLimit)
		}
	}
	if hits != 2 {
		t.Fatalf("made %d requests for 120 ids of 21 characters, want 2 batches under the cap", hits)
	}
}

func TestMalformedAliasCannotBecomeAQueryParameter(t *testing.T) {
	const bad = "CVE-2026-1&envelope=false&pretty=true"
	var got url.Values
	e := enrEnricher(t, enrKEV(), func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		io.WriteString(w, `{"status":"OK","total":1,"data":[{"cve":"CVE-2026-1234","epss":"0.5"}]}`)
	})

	fs := []finding.Finding{{ID: "GHSA-aaaa", Aliases: []string{bad, "CVE-2026-1234"}, Package: "p"}}
	res := e.Apply(context.Background(), fs)

	if got.Get("envelope") != "" || got.Get("pretty") != "" {
		t.Fatalf("an alias turned into query parameters: %v", got)
	}
	if strings.ContainsAny(got.Get("cve"), "&=") {
		t.Fatalf("cve parameter carries an unescaped separator: %q", got.Get("cve"))
	}
	if !fs[0].Exploit.EPSSKnown {
		t.Fatal("dropping the malformed alias must not drop the valid one beside it")
	}
	if !enrGapAbout(res.Gaps, bad) {
		t.Fatalf("a dropped identifier must leave a gap, got %v", res.Gaps)
	}
}

func TestErrorObjectInDataIsNotZeroScores(t *testing.T) {
	e := enrEnricher(t, enrKEV(), func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"status":"OK","data":{"error":["listNoResults"]}}`)
	})

	res := e.Apply(context.Background(), fixtures())
	if res.EPSSOK {
		t.Fatal("data as an error object must be an error, not a scoreless answer")
	}
	if !enrGapAbout(res.Gaps, epssFeed) {
		t.Fatalf("a refused EPSS request must leave a gap, got %v", res.Gaps)
	}
}

func TestShortPageIsNotZeroScores(t *testing.T) {
	e := enrEnricher(t, enrKEV(), func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"status":"OK","total":120,"data":[{"cve":"CVE-2026-0001","epss":"0.5"}]}`)
	})

	res := e.Apply(context.Background(), fixtures())
	if res.EPSSOK {
		t.Fatal("a page holding 1 of the 120 scores it reports must be an error")
	}
}

func TestBatchesStayUnderTheCharacterCap(t *testing.T) {
	ids := make([]string, 0, 400)
	for i := range 400 {
		ids = append(ids, fmt.Sprintf("CVE-2026-%d", 1000+i))
	}
	total := 0
	for _, batch := range epssBatches(ids) {
		joined := strings.Join(batch, ",")
		if len(joined) > epssJoinLimit {
			t.Fatalf("batch of %d ids joins to %d characters, over the %d cap",
				len(batch), len(joined), epssJoinLimit)
		}
		total += len(batch)
	}
	if total != len(ids) {
		t.Fatalf("batched %d of %d ids", total, len(ids))
	}
}
