package output

import (
	"cmp"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/FacileStudio/douane/internal/finding"
)

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
	sarifToolURI = "https://github.com/FacileStudio/douane"
	osvVulnURI   = "https://osv.dev/vulnerability/"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	ShortDescription sarifText `json:"shortDescription"`
	HelpURI          string    `json:"helpUri"`
}

type sarifText struct {
	Text string `json:"text"`
}

// sarifResult is one finding. A dependency has no line to point at, so its
// location is the lockfile with no region, and its fingerprint is supplied
// rather than left for the consumer to derive from source lines a lockfile
// does not have, which would move the alert on every reformat.
type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// sarifBuilder assembles one run: one rule per advisory id, in the order the
// ranking first meets it, and one result per finding.
type sarifBuilder struct {
	run  sarifRun
	seen map[string]bool
}

func newSarifBuilder() *sarifBuilder {
	driver := sarifDriver{Name: "douane", InformationURI: sarifToolURI, Rules: []sarifRule{}}
	run := sarifRun{Tool: sarifTool{Driver: driver}, Results: []sarifResult{}}
	return &sarifBuilder{seen: map[string]bool{}, run: run}
}

// add files one report's findings. prefix is prepended to each lockfile path
// and fingerprint, so a fleet run keeps two repositories' identical findings
// apart.
func (b *sarifBuilder) add(r Report, prefix string) {
	for _, f := range r.Findings {
		if !b.seen[f.ID] {
			b.seen[f.ID] = true
			desc := sarifText{Text: cmp.Or(f.Summary, f.ID)}
			b.run.Tool.Driver.Rules = append(b.run.Tool.Driver.Rules,
				sarifRule{ID: f.ID, ShortDescription: desc, HelpURI: osvVulnURI + f.ID})
		}
		b.run.Results = append(b.run.Results, sarifResultOf(f, prefix, r.Expired[f.Key()]))
	}
}

func sarifResultOf(f finding.Finding, prefix string, expired bool) sarifResult {
	where := sarifPhysical{ArtifactLocation: sarifArtifact{URI: prefix + filepath.ToSlash(f.Target)}}
	return sarifResult{
		RuleID:              f.ID,
		Level:               sarifLevel(f.Severity),
		Message:             sarifText{Text: sarifMessage(f, expired)},
		Locations:           []sarifLocation{{PhysicalLocation: where}},
		PartialFingerprints: map[string]string{"primaryLocationLineHash": prefix + f.Key()},
	}
}

func sarifReport(r Report) sarifLog {
	b := newSarifBuilder()
	b.add(r, "")
	return sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{b.run}}
}

func sarifSweep(s Sweep) sarifLog {
	b := newSarifBuilder()
	for _, r := range s.Repos {
		b.add(r, r.Name+"/")
	}
	return sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{b.run}}
}

// sarifLevel maps severity onto SARIF's three levels. Unknown is a note, not a
// warning: an unrated advisory is a question, and the text output already
// says so.
func sarifLevel(s finding.Severity) string {
	switch s {
	case finding.SevCritical, finding.SevHigh:
		return "error"
	case finding.SevMedium:
		return "warning"
	}
	return "note"
}

func sarifMessage(f finding.Finding, expired bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s is affected by %s", f.Package, f.Installed, f.ID)
	if f.Summary != "" {
		fmt.Fprintf(&b, ": %s", f.Summary)
	}
	if f.HasFix() {
		fmt.Fprintf(&b, ". Fixed in %s.", f.FixedIn)
	} else {
		b.WriteString(". No fix is available.")
	}
	if expired {
		b.WriteString(" EXPIRED PERMIT: the permit for this finding has lapsed.")
	}
	return b.String()
}
