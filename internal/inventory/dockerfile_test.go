package inventory

import (
	"reflect"
	"testing"

	"github.com/FacileStudio/douane/internal/finding"
)

const invRegistreDockerfile = `FROM golang:1.25-alpine AS api-build

ARG TARGETOS=linux

WORKDIR /repo/apps/api

COPY apps/api/go.mod apps/api/go.sum ./
RUN go mod download

COPY apps/api ./

RUN CGO_ENABLED=0 GOOS=${TARGETOS} \
    go build -trimpath -o bin/api .

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=api-build /repo/apps/api/bin/api /api

ENTRYPOINT ["/api"]
`

const invJournalDockerfile = `FROM oven/bun:1 AS client-build
WORKDIR /client
COPY apps/client/package.json apps/client/bun.lock* ./
RUN bun install --frozen-lockfile
COPY apps/client/ .
RUN bun run build

FROM golang:1.25-alpine AS api-build

WORKDIR /repo/apps/api

COPY apps/api/go.mod apps/api/go.sum ./
RUN go mod download

COPY apps/api ./

RUN CGO_ENABLED=0 go build -trimpath -o bin/api .

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=api-build /repo/apps/api/bin/api /api
COPY --from=client-build /client/build /client

ENTRYPOINT ["/api"]
`

func invBuildLines(t *testing.T, files map[string]string) (map[string]string, []finding.Gap) {
	t.Helper()
	return BuildLines(invTree(t, files))
}

func invWantLines(t *testing.T, got, want map[string]string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BuildLines = %v, want %v", got, want)
	}
}

// TestBuildLinesReadsTheBuilderImage is the whole point of the file: the go
// directive is a floor, and golang:1.25-alpine resolves at build time to the
// newest 1.25.x, so 1.22.0 in the go.mod is not what the binary ships.
func TestBuildLinesReadsTheBuilderImage(t *testing.T) {
	lines, gaps := invBuildLines(t, map[string]string{
		"Dockerfile":      invRegistreDockerfile,
		"apps/api/go.mod": "module x\n\ngo 1.22.0\n",
	})
	if len(gaps) != 0 {
		t.Fatalf("gaps = %+v, want none", gaps)
	}
	invWantLines(t, lines, map[string]string{"apps/api/go.mod": "1.25"})
}

// TestBuildLinesOnlyMapsWhatTheStageCopies pins the rule a repo-wide heuristic
// would break. Journal's golang stage copies apps/api/go.mod and nothing else,
// and sdk/journal is distributed as source: its consumers compile it, so its
// own go directive genuinely is the release it is built with.
func TestBuildLinesOnlyMapsWhatTheStageCopies(t *testing.T) {
	lines, gaps := invBuildLines(t, map[string]string{
		"Dockerfile":            invJournalDockerfile,
		"apps/api/go.mod":       "module x\n\ngo 1.25.0\n",
		"apps/collector/go.mod": "module x/collector\n\ngo 1.24.0\n",
		"sdk/journal/go.mod":    "module x/sdk\n\ngo 1.23.0\n",
	})
	if len(gaps) != 0 {
		t.Fatalf("gaps = %+v, want none", gaps)
	}
	invWantLines(t, lines, map[string]string{"apps/api/go.mod": "1.25"})
}

// TestBuildLinesKeepsAPinnedPatch: a tag that names a patch is the one case
// where the exact release is known, and rounding it back to the line would
// throw away the only precise answer a Dockerfile ever gives.
func TestBuildLinesKeepsAPinnedPatch(t *testing.T) {
	lines, _ := invBuildLines(t, map[string]string{
		"Dockerfile":      "FROM golang:1.25.7-bookworm AS b\nCOPY apps/api/go.mod ./\nRUN go build .\n",
		"apps/api/go.mod": "module x\n\ngo 1.25.0\n",
	})
	invWantLines(t, lines, map[string]string{"apps/api/go.mod": "1.25.7"})
}

// TestBuildLinesWithoutADockerfile: a repo that ships no image has nothing to
// correct, which is an empty answer and not a gap.
func TestBuildLinesWithoutADockerfile(t *testing.T) {
	lines, gaps := invBuildLines(t, map[string]string{"apps/api/go.mod": "module x\n\ngo 1.25.0\n"})
	if len(gaps) != 0 {
		t.Fatalf("gaps = %+v, want none", gaps)
	}
	invWantLines(t, lines, map[string]string{})
}

// TestBuildLinesUnnamedModuleIsAGap: a stage that builds a module it never
// named cannot be resolved, and guessing it would overwrite the release of
// whichever library the repo also publishes as source.
func TestBuildLinesUnnamedModuleIsAGap(t *testing.T) {
	lines, gaps := invBuildLines(t, map[string]string{
		"Dockerfile":      "FROM golang:1.25-alpine AS b\nCOPY . .\nRUN go build ./...\n",
		"apps/api/go.mod": "module x\n\ngo 1.25.0\n",
	})
	if len(gaps) != 1 || gaps[0].Kind != finding.GapUnresolved || gaps[0].Subject != "Dockerfile" {
		t.Fatalf("gaps = %+v, want one unresolved gap for Dockerfile", gaps)
	}
	invWantLines(t, lines, map[string]string{})
}

// TestBuildLinesUntaggedImageIsAGap: golang:latest names no release, and this
// file exists to stop douane inventing one.
func TestBuildLinesUntaggedImageIsAGap(t *testing.T) {
	lines, gaps := invBuildLines(t, map[string]string{
		"Dockerfile":      "FROM golang:latest\nCOPY apps/api/go.mod ./\nRUN go build .\n",
		"apps/api/go.mod": "module x\n\ngo 1.25.0\n",
	})
	if len(gaps) != 1 || gaps[0].Kind != finding.GapUnresolved {
		t.Fatalf("gaps = %+v, want one unresolved gap", gaps)
	}
	invWantLines(t, lines, map[string]string{})
}

// TestBuildLinesReadsEveryDockerfile: a repo can hold more than one image, and
// each golang stage in any of them names a module it builds.
func TestBuildLinesReadsEveryDockerfile(t *testing.T) {
	lines, gaps := invBuildLines(t, map[string]string{
		"Dockerfile":            invJournalDockerfile,
		"collector.Dockerfile":  "FROM golang:1.24-alpine\nCOPY apps/collector/go.mod ./\nRUN go build .\n",
		"apps/api/go.mod":       "module x\n\ngo 1.25.0\n",
		"apps/collector/go.mod": "module x/collector\n\ngo 1.21.0\n",
	})
	if len(gaps) != 0 {
		t.Fatalf("gaps = %+v, want none", gaps)
	}
	invWantLines(t, lines, map[string]string{
		"apps/api/go.mod":       "1.25",
		"apps/collector/go.mod": "1.24",
	})
}

// TestBuildLinesIgnoresVendoredDockerfiles: the walk skips the directories
// that hold installed artefacts, so a dependency's own image never speaks for
// the repo that vendored it.
func TestBuildLinesIgnoresVendoredDockerfiles(t *testing.T) {
	lines, _ := invBuildLines(t, map[string]string{
		"vendor/dep/Dockerfile":     "FROM golang:1.19-alpine\nCOPY go.mod ./\nRUN go build .\n",
		"node_modules/x/Dockerfile": "FROM golang:1.18-alpine\nCOPY go.mod ./\nRUN go build .\n",
		"go.mod":                    "module x\n\ngo 1.25.0\n",
	})
	invWantLines(t, lines, map[string]string{})
}

// TestBuildLinesDisagreeingStagesIsAGap: two images claiming different
// releases for one module cannot both be the deployed one, and the source
// alone does not say which is.
func TestBuildLinesDisagreeingStagesIsAGap(t *testing.T) {
	_, gaps := invBuildLines(t, map[string]string{
		"Dockerfile":      "FROM golang:1.25-alpine\nCOPY apps/api/go.mod ./\n",
		"dev.Dockerfile":  "FROM golang:1.24-alpine\nCOPY apps/api/go.mod ./\n",
		"apps/api/go.mod": "module x\n\ngo 1.24.0\n",
	})
	if len(gaps) != 1 || gaps[0].Kind != finding.GapUnresolved {
		t.Fatalf("gaps = %+v, want one unresolved gap", gaps)
	}
}

func TestGolangRelease(t *testing.T) {
	cases := []struct {
		args    string
		release string
		golang  bool
	}{
		{"golang:1.25-alpine AS api-build", "1.25", true},
		{"golang:1.25.7-bookworm", "1.25.7", true},
		{"golang:1.25", "1.25", true},
		{"docker.io/library/golang:1.26rc1-alpine", "1.26rc1", true},
		{"golang:1.25-alpine@sha256:abc", "1.25", true},
		{"golang:latest", "", true},
		{"golang:alpine", "", true},
		{"golang", "", true},
		{"oven/bun:1 AS client-build", "", false},
		{"gcr.io/distroless/static-debian12:nonroot", "", false},
		{"golangci/golangci-lint:v2", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		release, golang := golangRelease(c.args)
		if release != c.release || golang != c.golang {
			t.Fatalf("golangRelease(%q) = %q, %v; want %q, %v", c.args, release, golang, c.release, c.golang)
		}
	}
}

// TestCopyModulesSkipsDestinationAndStages: a destination named go.mod and a
// path copied out of an earlier stage both look like sources and are neither.
func TestCopyModulesSkipsDestinationAndStages(t *testing.T) {
	cases := map[string][]string{
		"apps/api/go.mod apps/api/go.sum ./":  {"apps/api/go.mod"},
		"a/go.mod b/go.mod ./":                {"a/go.mod", "b/go.mod"},
		"--from=build /repo/go.mod ./go.mod":  nil,
		"--chown=nonroot:nonroot a/go.mod ./": {"a/go.mod"},
		"go.mod ./go.mod":                     {"go.mod"},
		"apps/client/package.json ./":         nil,
	}
	for args, want := range cases {
		if got := copyModules(args); !reflect.DeepEqual(got, want) {
			t.Fatalf("copyModules(%q) = %v, want %v", args, got, want)
		}
	}
}

// TestDockerLogicalLinesJoinsContinuations: an instruction split across lines
// is one instruction, and reading it as several hides whichever part carried
// the go.mod.
func TestDockerLogicalLinesJoinsContinuations(t *testing.T) {
	got := dockerLogicalLines([]byte("# comment\nCOPY a/go.mod \\\n    b/go.mod \\\n    ./\n\nRUN go build .\n"))
	want := []string{"COPY a/go.mod b/go.mod ./", "RUN go build ."}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dockerLogicalLines = %q, want %q", got, want)
	}
}
