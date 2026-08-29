package osv

import (
	"context"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
)

// The live shape this exists for: a GO record carries no severity at all, its
// GHSA twin carries the label, and the CVE record that holds a vector has an
// empty affected[] so no package query can ever return it.
func osvChiRecords() map[string]Vuln {
	goRec := Vuln{ID: "GO-2026-5777", Aliases: []string{"CVE-2026-72816", "GHSA-rjr7-jggh-pgcp"}}

	ghsa := Vuln{ID: "GHSA-rjr7-jggh-pgcp", Aliases: []string{"CVE-2026-72816", "GO-2026-5777"}}
	ghsa.DatabaseSpecific = DatabaseSpecific{Severity: "HIGH"}
	ghsa.Severity = osvScore("CVSS_V4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N/E:P")

	cve := Vuln{ID: "CVE-2026-72816", Aliases: []string{"GHSA-rjr7-jggh-pgcp", "GO-2026-5777"}}
	cve.Severity = osvScore("CVSS_V4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N")

	return map[string]Vuln{goRec.ID: goRec, ghsa.ID: ghsa, cve.ID: cve}
}

func TestFetchResolvesSeverityAcrossTheAliasClosure(t *testing.T) {
	c, _ := osvVulnServer(t, osvChiRecords())
	out, gaps, err := c.Fetch(context.Background(), []string{"GO-2026-5777"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("gaps = %v, want none once the closure answers", gaps)
	}
	sev, vector := Severity(out["GO-2026-5777"])
	if sev != finding.SevHigh {
		t.Fatalf("severity = %v, want HIGH from the GHSA twin", sev)
	}
	if vector == "" {
		t.Fatal("the closure's CVSS vector must reach the record douane reports")
	}
}

// build() in the CLI keeps whichever record OSV happened to return first, so
// two twins of one flaw have to rate the same or the same commit gets two
// verdicts on two runs.
func TestFetchSeverityDoesNotDependOnWhichTwinIsKept(t *testing.T) {
	c, _ := osvVulnServer(t, osvChiRecords())
	ids := []string{"GO-2026-5777", "GHSA-rjr7-jggh-pgcp", "CVE-2026-72816"}
	out, _, err := c.Fetch(context.Background(), ids)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	for _, id := range ids {
		if sev, _ := Severity(out[id]); sev != finding.SevHigh {
			t.Fatalf("%s rates %v, want HIGH — every member of a closure is the same flaw", id, sev)
		}
	}
}

func TestFetchScoresTheClosureVectorWhenNoLabelExists(t *testing.T) {
	goRec := Vuln{ID: "GO-2026-4441", Aliases: []string{"CVE-2025-58190"}}
	cve := Vuln{ID: "CVE-2025-58190", Aliases: []string{"GO-2026-4441"}}
	cve.Severity = osvScore("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L")
	c, _ := osvVulnServer(t, map[string]Vuln{goRec.ID: goRec, cve.ID: cve})
	out, gaps, err := c.Fetch(context.Background(), []string{"GO-2026-4441"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("gaps = %v, want none — a 5.3 vector is a rating", gaps)
	}
	if sev, _ := Severity(out["GO-2026-4441"]); sev != finding.SevMedium {
		t.Fatalf("severity = %v, want MEDIUM from the closure's v3.1 vector", sev)
	}
}

func TestFetchGapsWhenNothingInTheClosureRates(t *testing.T) {
	c, _ := osvVulnServer(t, map[string]Vuln{"GO-2026-5932": {ID: "GO-2026-5932"}})
	out, gaps, err := c.Fetch(context.Background(), []string{"GO-2026-5932"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if sev, _ := Severity(out["GO-2026-5932"]); sev != finding.SevUnknown {
		t.Fatalf("severity = %v, want UNKNOWN", sev)
	}
	if len(gaps) != 1 || gaps[0].Kind != finding.GapSeverity || gaps[0].Subject != "GO-2026-5932" {
		t.Fatalf("gaps = %v, want a severity gap — UNKNOWN sits below every -fail threshold", gaps)
	}
}

func TestFetchLeavesARatedClosureAlone(t *testing.T) {
	c, hits := osvVulnServer(t, osvChiRecords())
	if _, _, err := c.Fetch(context.Background(), []string{"GHSA-rjr7-jggh-pgcp"}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("%d requests, want 1 — a record that already rates needs no closure", got)
	}
}

func TestFetchGapsAnAdvisoryItCouldNotRead(t *testing.T) {
	rated := Vuln{ID: "CVE-2026-1", DatabaseSpecific: DatabaseSpecific{Severity: "LOW"}}
	c, _ := osvVulnServer(t, map[string]Vuln{rated.ID: rated})
	out, gaps, err := c.Fetch(context.Background(), []string{"CVE-2026-1", "CVE-2026-2"})
	if err == nil {
		t.Fatal("an advisory that never arrived must be an error")
	}
	if len(out) != 1 {
		t.Fatalf("out = %v, want the record that did arrive", out)
	}
	if len(gaps) != 1 || gaps[0].Kind != finding.GapUnresolved || gaps[0].Subject != "CVE-2026-2" {
		t.Fatalf("gaps = %v, want one unresolved gap naming the missing id", gaps)
	}
}

// Some records name a GHSA twin OSV has no record for. The preferred fetch
// 404s, and a round that came back empty used to end the walk before the CVE
// twin holding the vector was ever asked for.
func TestFetchKeepsChasingWhenThePreferredTwinIsMissing(t *testing.T) {
	goRec := Vuln{ID: "GO-2026-5841", Aliases: []string{"GHSA-259r-337f-4rfw", "CVE-2026-3"}}
	cve := Vuln{ID: "CVE-2026-3", Aliases: []string{"GO-2026-5841"}}
	cve.Severity = osvScore("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
	c, _ := osvVulnServer(t, map[string]Vuln{goRec.ID: goRec, cve.ID: cve})
	out, gaps, err := c.Fetch(context.Background(), []string{goRec.ID})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("gaps = %v, want none, the CVE twin rates the closure", gaps)
	}
	if sev, _ := Severity(out[goRec.ID]); sev != finding.SevHigh {
		t.Fatalf("severity = %v, want HIGH from the CVE twin behind the missing GHSA", sev)
	}
	if id, _ := Canonical(out[goRec.ID], c.absent); id != "CVE-2026-3" {
		t.Fatalf("canonical = %q, want the CVE, which was never proven absent", id)
	}
}

// CVE-2024-24788 was retracted on 2025-02-28 and still answered a package
// query, so a record OSV itself no longer stands behind reached the report,
// the store's history and the exit code.
func TestFetchDropsAWithdrawnRecord(t *testing.T) {
	live := Vuln{ID: "CVE-2026-1", DatabaseSpecific: DatabaseSpecific{Severity: "LOW"}}
	gone := Vuln{ID: "CVE-2024-24788", Withdrawn: "2025-02-28T06:48:26.677625Z"}
	gone.DatabaseSpecific = DatabaseSpecific{Severity: "HIGH"}
	c, _ := osvVulnServer(t, map[string]Vuln{live.ID: live, gone.ID: gone})
	out, gaps, err := c.Fetch(context.Background(), []string{live.ID, gone.ID})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if _, ok := out[gone.ID]; ok {
		t.Fatal("a withdrawn advisory must not survive the fetch to become a finding")
	}
	if len(out) != 1 {
		t.Fatalf("out = %v, want only the live record", out)
	}
	if len(gaps) != 0 {
		t.Fatalf("gaps = %v, want none, a retraction is an answer and not a hole", gaps)
	}
}

// The GHSA twin is the one that carries a label, so a closure it settles must
// not also cost a request for the CVE twin that would add nothing.
func TestFetchTriesTheLabelledTwinFirst(t *testing.T) {
	c, hits := osvVulnServer(t, osvChiRecords())
	if _, _, err := c.Fetch(context.Background(), []string{"GO-2026-5777"}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("%d requests, want 2 — the record asked for, then its GHSA twin", got)
	}
}
