package osv

import (
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
)

func TestCVSS31ScoreMatchesTheSpecification(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N", 9.6},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N", 4.7},
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0},
	}
	for _, c := range cases {
		got, ok := cvss31Score(c.vector)
		if !ok {
			t.Errorf("cvss31Score(%q) refused a well-formed vector", c.vector)
			continue
		}
		if got != c.want {
			t.Errorf("cvss31Score(%q) = %.1f, want %.1f", c.vector, got, c.want)
		}
	}
}

func TestCVSS31SeverityBands(t *testing.T) {
	cases := []struct {
		vector string
		want   finding.Severity
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.SevCritical},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", finding.SevHigh},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", finding.SevMedium},
		{"CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", finding.SevLow},
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", finding.SevUnknown},
	}
	for _, c := range cases {
		if got := cvss31Severity(c.vector); got != c.want {
			t.Errorf("cvss31Severity(%q) = %v, want %v", c.vector, got, c.want)
		}
	}
}

func TestCVSS31SeverityRefusesWhatItCannotScore(t *testing.T) {
	cases := []string{
		"",
		"CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
		"CVSS:3.1/AV:N/AC:L/PR:N",
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	}
	for _, v := range cases {
		if got := cvss31Severity(v); got != finding.SevUnknown {
			t.Errorf("cvss31Severity(%q) = %v, want UNKNOWN — a guess is worse than a gap", v, got)
		}
	}
}
