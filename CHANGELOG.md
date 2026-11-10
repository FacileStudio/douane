# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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