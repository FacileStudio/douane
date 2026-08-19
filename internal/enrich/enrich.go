package enrich

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/FacileStudio/douane/internal/finding"
)

const (
	kevURL      = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
	epssURL     = "https://api.first.org/data/v1/epss"
	epssPerCall = 100
)

// Result reports which feeds answered. A feed being unreachable degrades the
// ranking, it never fails the sweep — but the caller must be able to say so.
type Result struct {
	KEVOK   bool
	EPSSOK  bool
	KEVErr  error
	EPSSErr error
}

// Enricher annotates findings with real-world exploitation signals.
type Enricher struct {
	http    *http.Client
	kevURL  string
	epssURL string
}

// New returns an Enricher pointed at the public KEV and EPSS feeds.
func New() *Enricher {
	return &Enricher{
		http:    &http.Client{Timeout: 30 * time.Second},
		kevURL:  kevURL,
		epssURL: epssURL,
	}
}

// Apply fills the exploitation signals of every finding in place.
func (e *Enricher) Apply(ctx context.Context, fs []finding.Finding) Result {
	var res Result
	kev, err := e.kev(ctx)
	if err != nil {
		res.KEVErr = err
	} else {
		res.KEVOK = true
		applyKEV(fs, kev)
	}

	scores, err := e.epss(ctx, cveIDs(fs))
	if err != nil {
		res.EPSSErr = err
		return res
	}
	res.EPSSOK = true
	applyEPSS(fs, scores)
	return res
}

func identifiers(f finding.Finding) []string {
	return append([]string{f.ID}, f.Aliases...)
}

func applyKEV(fs []finding.Finding, kev map[string]bool) {
	for i := range fs {
		for _, id := range identifiers(fs[i]) {
			ransomware, ok := kev[id]
			if !ok {
				continue
			}
			fs[i].Exploit.KEV = true
			fs[i].Exploit.Ransomware = ransomware
			break
		}
	}
}

func applyEPSS(fs []finding.Finding, scores map[string]float64) {
	for i := range fs {
		for _, id := range identifiers(fs[i]) {
			score, ok := scores[id]
			if !ok {
				continue
			}
			fs[i].Exploit.EPSS = score
			fs[i].Exploit.EPSSKnown = true
			break
		}
	}
}

func cveIDs(fs []finding.Finding) []string {
	set := map[string]bool{}
	for _, f := range fs {
		for _, id := range identifiers(f) {
			if strings.HasPrefix(id, "CVE-") {
				set[id] = true
			}
		}
	}
	return keys(set)
}
