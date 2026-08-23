package inventory

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
)

func invTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func invScan(t *testing.T, files map[string]string) ([]finding.Package, []finding.Gap) {
	t.Helper()
	pkgs, gaps, err := Scan(invTree(t, files))
	if err != nil {
		t.Fatal(err)
	}
	return pkgs, gaps
}

func invHas(pkgs []finding.Package, name, version string) bool {
	for _, p := range pkgs {
		if p.Name == name && p.Version == version {
			return true
		}
	}
	return false
}

func invGap(t *testing.T, gaps []finding.Gap, kind finding.GapKind, subject string) finding.Gap {
	t.Helper()
	for _, g := range gaps {
		if g.Kind == kind && g.Subject == subject {
			return g
		}
	}
	t.Fatalf("no %s gap for %q in %+v", kind, subject, gaps)
	return finding.Gap{}
}

// TestScanSurvivesAnUnreadableLockfile is the regression for the walk that
// aborted: returning the parse error up through WalkDir threw away every
// package already collected, so one stale fixture cost a repo its whole scan.
func TestScanSurvivesAnUnreadableLockfile(t *testing.T) {
	pkgs, gaps := invScan(t, map[string]string{
		"go.mod":                     "module x\n\ngo 1.25.0\n\nrequire github.com/a/b v1.2.3\n",
		"testdata/package-lock.json": "{not json",
	})
	if !invHas(pkgs, "github.com/a/b", "1.2.3") {
		t.Fatalf("the good lockfile lost its packages: %+v", pkgs)
	}
	invGap(t, gaps, finding.GapUnreadable, filepath.Join("testdata", "package-lock.json"))
}

// TestScanReportsReleaseModules proves the whole point of the go directive
// end to end: a repo scan now carries the two synthetic modules OSV answers
// Go toolchain advisories under.
func TestScanReportsReleaseModules(t *testing.T) {
	pkgs, gaps := invScan(t, map[string]string{"go.mod": "module x\n\ngo 1.25.0\n"})
	if len(gaps) != 0 {
		t.Fatalf("gaps = %+v, want none", gaps)
	}
	if !invHas(pkgs, "stdlib", "1.25.0") || !invHas(pkgs, "toolchain", "1.25.0") {
		t.Fatalf("packages = %+v, want stdlib and toolchain at 1.25.0", pkgs)
	}
	if src := pkgs[0].Source; src != "go.mod" {
		t.Fatalf("source = %q, want go.mod", src)
	}
}

// TestScanKeepsEveryGoRelease confirms the dedup key survives a workspace on
// two Go releases: keying on ecosystem, name and version means the second
// go.mod is a different stdlib, not a duplicate of the first.
func TestScanKeepsEveryGoRelease(t *testing.T) {
	pkgs, _ := invScan(t, map[string]string{
		"a/go.mod": "module a\n\ngo 1.24.0\n",
		"b/go.mod": "module b\n\ngo 1.25.0\n",
	})
	if !invHas(pkgs, "stdlib", "1.24.0") || !invHas(pkgs, "stdlib", "1.25.0") {
		t.Fatalf("packages = %+v, want stdlib at both releases", pkgs)
	}
}

func TestScanReportsUnsupportedEcosystems(t *testing.T) {
	_, gaps := invScan(t, map[string]string{
		"pnpm-lock.yaml":   "lockfileVersion: '9.0'\n",
		"api/Gemfile.lock": "GEM\n",
		"win/App.csproj":   "<Project/>\n",
		"py/uv.lock":       "version = 1\n",
		"orphan/go.sum":    "github.com/a/b v1.2.3 h1:x=\n",
		"kept/go.mod":      "module k\n\ngo 1.25.0\n",
		"kept/go.sum":      "github.com/a/b v1.2.3 h1:x=\n",
	})
	for _, subject := range []string{
		"pnpm-lock.yaml",
		filepath.Join("api", "Gemfile.lock"),
		filepath.Join("win", "App.csproj"),
		filepath.Join("py", "uv.lock"),
		filepath.Join("orphan", "go.sum"),
	} {
		invGap(t, gaps, finding.GapUnsupported, subject)
	}
	for _, g := range gaps {
		if g.Subject == filepath.Join("kept", "go.sum") {
			t.Fatalf("go.sum beside a go.mod is not an unsupported ecosystem: %+v", g)
		}
	}
}

// TestScanBinaryBunLock: the text lockfile is the migration target, so a repo
// that migrated and left the binary file committed has nothing wrong with it.
// Alone, the binary file is a real gap: douane cannot read it.
func TestScanBinaryBunLock(t *testing.T) {
	_, gaps := invScan(t, map[string]string{
		"bun.lock":  `{"lockfileVersion":1,"packages":{"left-pad":["left-pad@1.3.0"]}}`,
		"bun.lockb": "\x00binary",
	})
	if len(gaps) != 0 {
		t.Fatalf("gaps = %+v, want none beside a parsed bun.lock", gaps)
	}
	_, gaps = invScan(t, map[string]string{"bun.lockb": "\x00binary"})
	invGap(t, gaps, finding.GapUnreadable, "bun.lockb")
}

// TestScanDropsEmptyPackageName is the regression for the poisoned batch: a
// lockfile key ending exactly in "node_modules/" yields an empty name, and one
// empty name answers HTTP 400 for all 500 packages in its OSV request.
func TestScanDropsEmptyPackageName(t *testing.T) {
	pkgs, gaps := invScan(t, map[string]string{
		"package-lock.json": `{"packages":{"":{"version":"1.0.0"},` +
			`"node_modules/":{"version":"9.9.9"},` +
			`"node_modules/left-pad":{"version":"1.3.0"}}}`,
	})
	for _, p := range pkgs {
		if p.Name == "" || p.Version == "" {
			t.Fatalf("emitted an unqueryable package: %+v", pkgs)
		}
	}
	if !invHas(pkgs, "left-pad", "1.3.0") {
		t.Fatalf("packages = %+v, want left-pad", pkgs)
	}
	invGap(t, gaps, finding.GapUnreadable, "package-lock.json")
}

// TestScanUnreadableRootIsFatal: a target douane cannot open at all is bad
// input, not a scan with a hole in it.
func TestScanUnreadableRootIsFatal(t *testing.T) {
	if _, _, err := Scan(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("Scan of a missing target returned no error")
	}
}
