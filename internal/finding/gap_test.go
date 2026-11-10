package finding

import "testing"

func TestEveryGapKindIsClassifiedByWhatItCanHide(t *testing.T) {
	for _, tc := range []struct {
		gap  Gap
		want bool
	}{
		{Gap{Kind: GapUpstream}, true},
		{Gap{Kind: GapUnreadable}, true},
		{Gap{Kind: GapUnsupported}, true},
		{Gap{Kind: GapUnresolved}, true},
		{Gap{Kind: GapSeverity, Advisory: "GO-2026-1"}, false},
		{Gap{Kind: GapRange, Advisory: "GO-2026-1"}, false},
		{Gap{Kind: GapUpstream, Annotation: true}, false},
		{Gap{Kind: GapUnreadable, Annotation: true}, false},
		{Gap{Kind: GapUnresolved, Annotation: true}, false},
		{Gap{Kind: GapUnsupported, Annotation: true}, false},
		{Gap{Kind: GapSeverity, Annotation: true}, false},
		{Gap{Kind: "a kind added later"}, true},
	} {
		if got := tc.gap.HidesFindings(); got != tc.want {
			t.Errorf("%+v: HidesFindings = %t, want %t", tc.gap, got, tc.want)
		}
	}
}
