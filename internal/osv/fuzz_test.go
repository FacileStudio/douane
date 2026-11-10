package osv

import (
	"testing"
	"time"
)

func FuzzCompareVersions(f *testing.F) {
	for _, pair := range [][2]string{
		{"1.2.3", "1.2.3"}, {"1.10.0", "1.9.0"}, {"1.0.0", "1.0"}, {"1.0.0-rc1", "1.0.0"},
		{"v1.24.0", "1.24.0"}, {"24.0.5+incompatible", "24.0.4"}, {"1.0.0-rc.2", "1.0.0-rc.10"},
		{"1.24.0-0", "1.24.0"}, {"", "-"}, {"99999999999999999999", "1"},
	} {
		f.Add(pair[0], pair[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		if len(a)+len(b) > 1<<20 {
			t.Skip()
		}
		start := time.Now()
		ab, ba := compareVersions(a, b), compareVersions(b, a)
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("compare took %s", elapsed)
		}
		if ab != -ba {
			t.Fatalf("compareVersions(%q, %q) = %d but the reverse is %d", a, b, ab, ba)
		}
		if compareVersions(a, a) != 0 {
			t.Fatalf("compareVersions(%q, itself) != 0", a)
		}
	})
}

func FuzzCVSS31(f *testing.F) {
	for _, v := range []string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
		"CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"CVSS:3.1/AV:N/AV:X", "CVSS:3.", "",
	} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, vector string) {
		if len(vector) > 1<<20 {
			t.Skip()
		}
		start := time.Now()
		score, ok := cvss31Score(vector)
		cvss31Severity(vector)
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("score took %s", elapsed)
		}
		if ok && (score < 0 || score > 10) {
			t.Fatalf("cvss31Score(%q) = %v, outside 0 to 10", vector, score)
		}
	})
}
