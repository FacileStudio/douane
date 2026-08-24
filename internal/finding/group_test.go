package finding_test

import (
	"strings"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
)

func grpFinding(id, installed string, kev bool) finding.Finding {
	return finding.Finding{ID: id, Package: "chi", Ecosystem: "Go",
		Installed: installed, FixedIn: "5.0.12", Severity: finding.SevHigh,
		Target: "go.mod", Exploit: finding.Exploit{KEV: kev}}
}

func TestGroupsCollapseToTheFix(t *testing.T) {
	gs := finding.Groups([]finding.Finding{
		grpFinding("GO-1", "5.0.0", false),
		grpFinding("GO-2", "4.11.0", false),
	}, nil)
	if len(gs) != 1 {
		t.Fatalf("groups = %d, want one per fix, got %+v", len(gs), gs)
	}
	g := gs[0]
	if g.Count != 2 || g.FixedIn != "5.0.12" {
		t.Fatalf("group = %+v, want count 2 at fix 5.0.12", g)
	}
	if len(g.IDs) != 2 || len(g.Installed) != 2 {
		t.Fatalf("group = %+v, want both ids and both versions carried", g)
	}
}

// TestGroupsKeepNoFixApart pins that a package with no available fix is its
// own group: upgrading to nothing is not the same decision as upgrading.
func TestGroupsKeepNoFixApart(t *testing.T) {
	noFix := grpFinding("GO-3", "5.0.0", false)
	noFix.FixedIn = ""
	gs := finding.Groups([]finding.Finding{grpFinding("GO-1", "5.0.0", false), noFix}, nil)
	if len(gs) != 2 {
		t.Fatalf("groups = %d, want the no-fix package kept apart:\n%+v", len(gs), gs)
	}
	var sawFix, sawNoFix bool
	for _, g := range gs {
		switch g.FixedIn {
		case "5.0.12":
			sawFix = true
		case "":
			sawNoFix = true
		}
	}
	if !sawFix || !sawNoFix {
		t.Fatalf("groups = %+v, want one fix group and one no-fix group", gs)
	}
}

func TestGroupsCarryWorstAndKEV(t *testing.T) {
	mid := grpFinding("GO-4", "5.0.0", false)
	mid.Severity = finding.SevMedium
	kev := grpFinding("GO-5", "4.11.0", true)
	gs := finding.Groups([]finding.Finding{mid, kev}, nil)
	if len(gs) != 1 || !gs[0].KEV {
		t.Fatalf("groups = %+v, want one KEV-marked group", gs)
	}
	if gs[0].Worst != finding.SevHigh || gs[0].WorstFinding().ID != "GO-5" {
		t.Fatalf("worst = %s/%s, want the critical member to speak for the group",
			gs[0].Worst, gs[0].WorstFinding().ID)
	}
}

func TestGroupsCountNewThroughThePredicate(t *testing.T) {
	f1 := grpFinding("GO-1", "5.0.0", false)
	f2 := grpFinding("GO-2", "4.11.0", false)
	gs := finding.Groups([]finding.Finding{f1, f2}, func(f finding.Finding) bool {
		return f.ID == "GO-2"
	})
	if gs[0].New != 1 {
		t.Fatalf("new = %d, want only the unseen finding counted", gs[0].New)
	}
}

// TestGroupsOrderVersionsNumerically guards the display order: lexical sort
// puts 4.11.0 before 4.9.0, which reads as a downgrade.
func TestGroupsOrderVersionsNumerically(t *testing.T) {
	gs := finding.Groups([]finding.Finding{
		grpFinding("GO-1", "4.11.0", false),
		grpFinding("GO-2", "4.9.0", false),
	}, nil)
	want := "4.9.0, 4.11.0"
	if got := strings.Join(gs[0].Installed, ", "); got != want {
		t.Fatalf("installed = %q, want %q — versions must sort numerically", got, want)
	}
}
