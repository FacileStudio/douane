# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.6.2] - 2026-11-10

### Fixed
- A finding's key no longer follows the identifier douane reports it under. The key is built from the smallest name the flaw has, so an advisory that flips between its CVE and its GHSA alias between runs is no longer read as one finding resolved and one new. History written under the old keys still matches, so the first run after upgrading does not mark everything new.

### Added
- gofmt formatting applied across the codebase

## [v0.6.1]

*Released after v0.6.0.*