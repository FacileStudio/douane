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
	}, nil, nil)
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
	gs := finding.Groups([]finding.Finding{grpFinding("GO-1", "5.0.0", false), noFix}, nil, nil)
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
	gs := finding.Groups([]finding.Finding{mid, kev}, nil, nil)
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
	}, nil)
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
	}, nil, nil)
	want := "4.9.0, 4.11.0"
	if got := strings.Join(gs[0].Installed, ", "); got != want {
		t.Fatalf("installed = %q, want %q — versions must sort numerically", got, want)
	}
}

func stdlibFinding(id, fixedIn string) finding.Finding {
	return finding.Finding{ID: id, Package: "stdlib", Ecosystem: "Go",
		Installed: "1.25.0", FixedIn: fixedIn, Severity: finding.SevHigh,
		Target: "go.mod"}
}

// TestGroupsMergeOneReleaseLine pins the Registre case: six stdlib advisories
// fixed in six different patches are one bump, not six.
func TestGroupsMergeOneReleaseLine(t *testing.T) {
	var fs []finding.Finding
	for _, v := range []string{"1.25.8", "1.25.9", "1.25.10", "1.25.11", "1.25.12", "1.25.13"} {
		fs = append(fs, stdlibFinding("GO-"+v, v))
	}
	gs := finding.Groups(fs, nil, nil)
	if len(gs) != 1 {
		t.Fatalf("groups = %d, want one bump for one release line:\n%+v", len(gs), gs)
	}
	if gs[0].FixedIn != "1.25.13" {
		t.Fatalf("fixed_in = %q, want the highest patch that clears every member", gs[0].FixedIn)
	}
	if gs[0].Count != 6 || len(gs[0].IDs) != 6 {
		t.Fatalf("group = %+v, want all six findings carried", gs[0])
	}
}

// TestGroupsKeepReleaseLinesApart pins the Journal case: two modules on two Go
// lines must stay two decisions, because 1.24.13 is a patch and 1.25.13 is not.
func TestGroupsKeepReleaseLinesApart(t *testing.T) {
	gs := finding.Groups([]finding.Finding{
		stdlibFinding("GO-a", "1.24.2"),
		stdlibFinding("GO-b", "1.24.13"),
		stdlibFinding("GO-c", "1.25.6"),
		stdlibFinding("GO-d", "1.25.13"),
	}, nil, nil)
	if len(gs) != 2 {
		t.Fatalf("groups = %d, want one per release line:\n%+v", len(gs), gs)
	}
	got := map[string]int{}
	for _, g := range gs {
		got[g.FixedIn] = g.Count
	}
	if got["1.24.13"] != 2 || got["1.25.13"] != 2 {
		t.Fatalf("groups = %+v, want 1.24.13 and 1.25.13 with two findings each", gs)
	}
}

// TestGroupsNeverMergeIntoNoFix pins that a package with no fix stays apart
// from a fixed one: merging would claim a fix that does not exist.
func TestGroupsNeverMergeIntoNoFix(t *testing.T) {
	gs := finding.Groups([]finding.Finding{
		stdlibFinding("GO-a", "1.25.8"),
		stdlibFinding("GO-b", "1.25.13"),
		stdlibFinding("GO-c", ""),
	}, nil, nil)
	if len(gs) != 2 {
		t.Fatalf("groups = %d, want the no-fix finding kept apart:\n%+v", len(gs), gs)
	}
	for _, g := range gs {
		if g.FixedIn == "" && g.Count != 1 {
			t.Fatalf("no-fix group = %+v, want it alone", g)
		}
	}
}

// TestGroupsMergePreserveEveryFinding pins losslessness across the merge: the
// counts, the KEV flag and the worst member survive folding.
func TestGroupsMergePreserveEveryFinding(t *testing.T) {
	low := stdlibFinding("GO-a", "1.25.8")
	low.Severity = finding.SevLow
	kev := stdlibFinding("GO-b", "1.25.13")
	kev.Severity = finding.SevMedium
	kev.Exploit = finding.Exploit{KEV: true}
	gs := finding.Groups([]finding.Finding{low, kev}, func(f finding.Finding) bool {
		return f.ID == "GO-b"
	}, nil)
	g := gs[0]
	if g.Count != 2 || g.New != 1 || !g.KEV {
		t.Fatalf("group = %+v, want count 2, one new, KEV carried", g)
	}
	if g.Worst != finding.SevMedium || g.WorstFinding().ID != "GO-b" {
		t.Fatalf("worst = %s/%s, want the KEV member to speak for the merged group",
			g.Worst, g.WorstFinding().ID)
	}
}
