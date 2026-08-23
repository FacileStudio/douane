package output_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
	"github.com/FacileStudio/douane/internal/output"
)

func TestJSONCarriesNewCompleteAndSchema(t *testing.T) {
	stdout, _ := outWriteTo(t, output.JSON, outReport())
	var doc struct {
		SchemaVersion string `json:"schema_version"`
		Complete      bool   `json:"complete"`
		Findings      []struct {
			ID  string `json:"id"`
			Key string `json:"key"`
			New bool   `json:"new"`
		} `json:"findings"`
		Gaps []finding.Gap `json:"gaps"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("decode %s: %v", stdout, err)
	}
	if doc.SchemaVersion != output.SchemaVersion {
		t.Fatalf("schema_version = %q, want %q", doc.SchemaVersion, output.SchemaVersion)
	}
	if doc.Complete {
		t.Fatal("complete = true on a report holding a gap")
	}
	if len(doc.Findings) != 1 || !doc.Findings[0].New {
		t.Fatalf("findings = %+v, want one marked new", doc.Findings)
	}
	if doc.Findings[0].Key != outFinding("GO-1").Key() {
		t.Fatalf("key = %q, want the history key", doc.Findings[0].Key)
	}
	if len(doc.Gaps) != 1 || doc.Gaps[0].Kind != finding.GapUpstream {
		t.Fatalf("gaps = %+v, want the upstream gap", doc.Gaps)
	}
}

// TestJSONEmitsArraysNotNull keeps `jq '.findings | length'` working on a
// clean run, which is the shape CI checks first.
func TestJSONEmitsArraysNotNull(t *testing.T) {
	stdout, _ := outWriteTo(t, output.JSON, output.Report{Target: "/repo"})
	for _, want := range []string{`"findings": []`, `"gaps": []`, `"complete": true`} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("json = %s, want it to carry %s", stdout, want)
		}
	}
}
