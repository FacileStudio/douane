# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.7.2] - 2026-11-10

### Fixed
- A gap that concerns only findings `-scope` filtered out no longer counts toward exit 3. A `severity` gap for an advisory whose only finding is dev-only, under `-scope prod`, kept the run incomplete although the reader chose not to look at that finding. Such a gap leaves `gaps` and is listed under `out_of_scope_gaps` in JSON, on the repository and, for a fleet gap, at the sweep's root. A gap that also concerns a finding still in scope stays, and a gap about the scan itself concerns no finding, so the scope never removes it.
- A run carrying a gap that can hide findings for a repository writes no history row for it: a failed OSV query, an unreadable or unsupported lockfile among readable ones, an advisory or package that did not resolve. The previous row stays, so the next complete run does not report the findings this run missed as NEW. A gap that only qualifies a reported finding (`severity`, `range`) or a label on one (a KEV or EPSS feed outage, a Dockerfile build line douane could not read) does not block the write. `Gap.HidesFindings` is the one place that classifies gaps this way.

## [v0.7.1] - 2026-11-10

### Fixed
- A valid permit now covers the gaps its finding alone raised. An advisory with no severity anywhere raised a `severity` gap that outlived the permit suppressing its finding, so the run stayed incomplete and exited 3. A `severity`, `range` or EPSS-identifier gap leaves `gaps` when every finding it concerns is permitted, and JSON lists it under that finding's `gaps` in `permitted`. In a sweep a fleet gap is covered only when no repository still reports a finding it concerns. A gap about the scan itself, such as an unreadable lockfile, a feed outage, an advisory record that never arrived or an invalid `douane.yml`, is never covered.
- Directories named `testdata` are skipped by the lockfile walk, the Dockerfile walk and sweep discovery, like `vendor` and `node_modules`. A deliberately broken fixture such as `testdata/Dockerfile.bad` no longer reads as a build file that could not be resolved.
- A repository a sweep skipped, or one that yielded no package, no longer writes an empty history row. Its previous row stands, so the next good run does not report every finding as new.

### Added
- `-include-testdata` reads `testdata` directories again.
- douane is released under the [GNU General Public License v3.0 only](LICENSE) (`GPL-3.0-only`).

## [v0.7.0] - 2026-11-10

### Added
- Permits: `douane.yml` at a project's root suppresses a finding by any of its names, optionally narrowed to one package. Every entry needs a `reason` and an `expires` date at most 365 days ahead; a missing field, an unknown key or a bad date exits 2 with the file and line. A permitted finding leaves the output and the `-fail` calculation and is listed under `permitted` in JSON. A lapsed permit returns its finding marked `EXPIRED PERMIT` and exits 1 whatever `-fail` says. Permits expiring within 14 days are listed on stderr on every run. In a sweep, each repository reads its own file only, and an invalid one is an `unreadable` gap on that repository instead of a usage error: stderr names the file and line, that repository is skipped, every other one is swept, and the sweep exits 3 unless findings at or above `-fail` make it exit 1. `douane scan` on one project still exits 2.
- `-format sarif` writes SARIF 2.1.0: one rule per advisory, one result per finding at its lockfile with no region, fingerprinted with the finding's history key.
- Fuzz targets for every parser of untrusted input: go.mod, package-lock.json, bun.lock and its JSONC reader, Cargo.lock, Dockerfiles, OSV version comparison, CVSS v3 vectors and douane.yml.

### Changed
- The JSON report carries a `permitted` array, always present, and `expired_permit` on a finding a lapsed permit gave back. Groups carry `expired_permits`. A line-format finding a lapsed permit gave back ends its bracket with `permit=expired`.

## [v0.6.3] - 2026-11-10

### Fixed
- In a sweep, a failed OSV query or a missing advisory record is now also a gap on every repository it can have emptied, so an outage no longer reads as repositories that are complete with no findings.
- A response body over the size limit is an error instead of a silently shortened answer.

### Changed
- A finding is keyed by its best-ranked name (CVE, then GHSA, then the ecosystem's own id, then anything else) instead of its smallest name, so an alias OSV adds later, such as a BIT- copy, no longer moves the key. Keys move once from v0.6.2 for findings whose smallest name was not their CVE; the sweep database still matches them, a run with `-db ""` does not.
- Releases build with `-trimpath` from the Go version in `go.mod`, run vet and tests first, pin every action to a commit and attest each archive's build provenance.

### Added
- `-timeout` bounds a whole run, 10 minutes by default.
- A CI workflow runs gofmt, vet and tests on every push to main and every pull request.

## [v0.6.2] - 2026-11-10

### Fixed
- A finding's key no longer follows the identifier douane reports it under. The key is built from the smallest name the flaw has, so an advisory that flips between its CVE and its GHSA alias between runs is no longer read as one finding resolved and one new. When the sweep database is on, history written under the old keys still matches, so the first run after upgrading does not mark everything new; a run with `-db ""` has no history to match.

### Added
- gofmt formatting applied across the codebase

## [v0.6.1]

*Released after v0.6.0.*