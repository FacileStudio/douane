package enrich

import (
	"fmt"
	"time"

	"github.com/FacileStudio/douane/internal/finding"
)

// enrGaps records every axis the run could not determine. A feed that did not
// answer is not a warning about ranking quality, it is a hole in the answer:
// with no catalogue every finding reads as not-exploited, so -fail kev passes
// a scan that measured nothing. A cache past its TTL is reported too, because
// KEV grows daily and yesterday's catalogue cannot rule today's flaw in.
func enrGaps(res *Result, malformed []string) []finding.Gap {
	var out []finding.Gap
	switch {
	case !res.KEVOK:
		out = append(out, enrGap(kevFeed,
			fmt.Sprintf("catalogue unavailable, nothing was checked against it: %v", res.KEVErr)))
	case res.KEVStale:
		out = append(out, enrGap(kevFeed,
			fmt.Sprintf("feed unreachable, catalogue served from a cache %s old", enrAge(res.KEVAge))))
	}
	switch {
	case !res.EPSSOK:
		out = append(out, enrGap(epssFeed, fmt.Sprintf("scores unavailable: %v", res.EPSSErr)))
	case res.EPSSStale:
		out = append(out, enrGap(epssFeed, "feed unreachable, scores served from the cache alone"))
	}
	for _, id := range malformed {
		out = append(out, enrGap(epssFeed,
			fmt.Sprintf("dropped %q: not a CVE identifier, so it was never scored", id)))
	}
	return out
}

func enrGap(subject, detail string) finding.Gap {
	return finding.Gap{Kind: finding.GapUpstream, Subject: subject, Detail: detail}
}

func enrAge(d time.Duration) string {
	if d < time.Hour {
		return "under an hour"
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}
