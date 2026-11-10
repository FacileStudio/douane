package permit

import (
	"testing"
	"time"
)

func FuzzParse(f *testing.F) {
	today := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	for _, s := range []string{
		"permits:\n  - id: GHSA-aaaa-bbbb-cccc\n    package: golang.org/x/crypto\n    reason: no fix # c\n    expires: 2027-01-31\n",
		"permits:\n- id: \"CVE-2026-1\"\n  reason: 'it''s fine: really'\n  expires: \"2026-11-20\"\n",
		"permits: []\n", "\ufeffpermits:\r\n  - id: X\r\n", "permits:\n  - id: \"\\x\"\n", "permits:\n  -\n", "",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		start := time.Now()
		permits, err := Parse(data, today)
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("Parse took %s on %d bytes", elapsed, len(data))
		}
		if err != nil {
			return
		}
		for _, p := range permits {
			if p.ID == "" || p.Reason == "" || p.Expires.IsZero() || p.Expires.Sub(today) > MaxAhead || p.Line < 1 {
				t.Fatalf("Parse accepted an invalid permit %+v", p)
			}
		}
	})
}
