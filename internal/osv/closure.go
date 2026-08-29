package osv

import (
	"context"
	"maps"
	"slices"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

// closureRounds bounds how far the alias closure is chased. One round covers
// every shape measured — a GO record names its GHSA and CVE twins directly —
// and the bound is what stops a chain of records that keep naming new aliases
// from turning one finding into an unbounded crawl.
const closureRounds = 3

// hydrate resolves severity across each alias closure and writes the answer
// onto every record in it.
//
// A GO record carries neither a severity label nor a CVSS vector; its GHSA twin
// carries both, and the CVE record holding the vector often has an empty
// affected[], so no package query can ever return it — it is reachable only
// through the alias link. Whichever member of a closure a caller keeps for a
// finding, it has to read the same severity, so the answer is stamped on all of
// them instead of being left where it was found.
func (c *Client) hydrate(ctx context.Context, held map[string]Vuln, want []string) []finding.Gap {
	tried := make(map[string]bool, len(want))
	for _, id := range want {
		tried[id] = true
	}
	for range closureRounds {
		missing := unresolvedMembers(held, tried)
		if len(missing) == 0 {
			break
		}
		for _, id := range missing {
			tried[id] = true
		}
		more, _ := c.fetchSet(ctx, missing)
		maps.Copy(held, more)
	}
	for _, group := range closures(held) {
		label, score := closureSeverity(held, group)
		stamp(held, group, label, score)
	}
	return severityGaps(held, want, c.absent)
}

// unresolvedMembers lists the closure members worth fetching: those in a
// closure that still has no severity. A closure that already answers is left
// alone, which is what keeps the extra requests proportional to the findings
// douane cannot rate rather than to every finding it has.
func unresolvedMembers(held map[string]Vuln, tried map[string]bool) []string {
	var missing []string
	for _, group := range closures(held) {
		if label, _ := closureSeverity(held, group); label != "" {
			continue
		}
		missing = append(missing, missingFrom(held, tried, group)...)
	}
	return missing
}

// missingFrom picks which members of an unrated closure to fetch. GHSA records
// go first, alone: they are the ones carrying a curated label, and measured
// against the live API they settle 113 closures in 120, so pulling the CVE twin
// in the same round would be a request that changes nothing. The rest wait for
// the next round, which only happens for a closure the GHSA did not settle.
//
// A round that fetched nothing at all still has to hand over to the next one.
// Some records name a GHSA twin OSV has no record for, so the preferred fetch
// 404s and comes back empty; treating that as the end of the walk stranded the
// CVE twin that would have rated the closure, and left 8 of the fleet's 43
// severity gaps sitting on a record whose rating was one request away.
func missingFrom(held map[string]Vuln, tried map[string]bool, group []string) []string {
	var preferred, rest []string
	for _, id := range group {
		if _, ok := held[id]; ok || tried[id] {
			continue
		}
		if strings.HasPrefix(id, "GHSA-") {
			preferred = append(preferred, id)
			continue
		}
		rest = append(rest, id)
	}
	if len(preferred) > 0 {
		return preferred
	}
	return rest
}

// closures groups the held records into alias closures: records that name each
// other, transitively, describe one flaw. Groups and members are sorted so no
// answer downstream depends on Go's map order.
func closures(held map[string]Vuln) [][]string {
	adj := map[string][]string{}
	for id, v := range held {
		adj[id] = append(adj[id], v.Aliases...)
		for _, a := range v.Aliases {
			adj[a] = append(adj[a], id)
		}
	}
	seen := map[string]bool{}
	var out [][]string
	for _, id := range slices.Sorted(maps.Keys(adj)) {
		if seen[id] {
			continue
		}
		out = append(out, closureAt(adj, seen, id))
	}
	return out
}

func closureAt(adj map[string][]string, seen map[string]bool, from string) []string {
	var group []string
	stack := []string{from}
	for len(stack) > 0 {
		at := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[at] {
			continue
		}
		seen[at] = true
		group = append(group, at)
		stack = append(stack, adj[at]...)
	}
	slices.Sort(group)
	return group
}

// stamp writes the closure's answer onto every member it holds. The records are
// mutated deliberately: Severity is handed one record, so the only place an
// alias-closure answer can survive to whichever member the caller kept is on
// the records themselves.
func stamp(held map[string]Vuln, group []string, label string, score SeverityScore) {
	for _, id := range group {
		v, ok := held[id]
		if !ok {
			continue
		}
		if label != "" {
			v.DatabaseSpecific.Severity = label
		}
		if len(v.Severity) == 0 && score.Score != "" {
			v.Severity = []SeverityScore{score}
		}
		held[id] = v
	}
}

// severityGaps reports the requested advisories no member of their closure
// could rate. An unrated finding sits below every -fail threshold, so without
// this the CI gate passes over it in silence.
func severityGaps(held map[string]Vuln, want []string, absent map[string]bool) []finding.Gap {
	var gaps []finding.Gap
	for _, id := range want {
		v, ok := held[id]
		if !ok {
			continue
		}
		if sev, _ := Severity(v); sev != finding.SevUnknown {
			continue
		}
		canonical, _ := Canonical(v, absent)
		gaps = append(gaps, finding.Gap{
			Kind:    finding.GapSeverity,
			Subject: canonical,
			Detail:  "no severity label or scorable CVSS vector in the alias closure",
		})
	}
	return gaps
}
