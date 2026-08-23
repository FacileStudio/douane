package osv

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.10.0", "1.9.0", 1},
		{"2.5.6", "4.0.5", -1},
		{"8.21.0", "8.20.1", 1},
		{"1.0.0", "1.0", 0},
		{"1.0.0-rc1", "1.0.0", -1},
		{"v1.24.0", "1.24.0", 0},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareVersionsIgnoresBuildMetadata(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0+x", "1.0.0", 0},
		{"1.0.0+x", "1.0.0+y", 0},
		{"24.0.5+incompatible", "24.0.4", 1},
		{"1.0.0-rc.1+build", "1.0.0-rc.1", 0},
		{"1.0.0-rc.1+build", "1.0.0", -1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d (semver: build metadata carries no ordering)",
				c.a, c.b, got, c.want)
		}
	}
}

func TestComparePrereleaseIsNotLexical(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0-rc.2", "1.0.0-rc.10", -1},
		{"1.0.0-rc.10", "1.0.0-rc.9", 1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-1", "1.0.0-alpha", -1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// The Go advisory format opens a major branch with a "-0" pre-release so that
// the branch marker sorts below every release on it.
func TestCompareVersionsHandlesGoBranchMarkers(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.24.0-0", "1.24.0", -1},
		{"1.24.0-0", "1.23.7", 1},
		{"1.24.0-0", "1.24.1", -1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
