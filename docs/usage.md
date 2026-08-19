# Usage

## `douane scan [path]`

Reads every lockfile under `path`, resolves vulnerabilities, and prints them ranked.
Defaults to the current directory.

### Flags

| Flag | Values | Default | Effect |
|---|---|---|---|
| `-format` | `auto`, `text`, `line`, `json` | `auto` | Output shape |
| `-fail` | `never`, `low`, `medium`, `high`, `critical`, `kev` | `never` | Exit 1 at or above |
| `-db` | path, or `""` | `~/.douane.db` | Sweep history; `""` disables it |
| `-no-enrich` | — | off | Skip the KEV and EPSS feeds |
| `-refresh` | — | off | Refetch the feeds, ignoring the cache |

## `douane sweep [dir]`

Scans every repository directly under `dir` and reports across all of them, grouped by
repository and ranked globally. A directory counts as a repository when it holds a `.git`
or a lockfile at its top level; `sweep` does not recurse past that, so a monorepo is one
repository, not one per app.

Takes the same flags as `scan`. A repository with an unreadable lockfile does not stop the
others — it is reported, skipped, and counted in the summary — but the sweep still exits 2,
because a repository that silently leaves the fleet is a false negative, not a clean run.

```
GFConseil — 122 held out of 1065 packages

HIGH      CVE-2026-44578 next@16.0.10
          epss 38.87% · fix 16.2.5 · npm · package-lock.json
          ...

  GFConseil    122 findings    1065 packages
  LauraHerve    92 findings     808 packages
  ...

732 held out of 8175 packages across 27 repos — 2 clear
```

### Why it is not a loop over `scan`

The packages of sibling projects overlap almost completely, so `sweep` collects every
inventory first, resolves the **union** once, and splits the findings back out per
repository. Each repository still reports its own lockfile paths and its own history diff.

## Feed cache

KEV and EPSS are cached in the sweep database for 24 hours — the catalogue whole, EPSS one
row per CVE, including the CVEs it has no score for so they are not re-queried. A second
run inside the TTL makes no request to either feed.

If a feed is unreachable and the cache has expired, douane uses it anyway and says so:

```
  ! KEV feed unreachable — using a cached catalogue from 31h ago
```

`-refresh` forces a fetch. `-db ""` disables the database, and with it the cache.

### Formats

`auto` resolves to `text` on a terminal and `line` everywhere else. Pass `-format text`
explicitly if you want the human report from a script.

**line** — one finding per line, greppable:

```
npm:shell-quote@1.8.3: critical: CVE-2026-9277 [bun.lock epss=0.0085 kev=false fix=1.8.4]
```

**json** — the full report, including `aliases`, the CVSS vector and the `exploit` block.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Clear, or findings below `-fail` |
| 1 | Findings at or above `-fail` |
| 2 | Bad usage, unreadable lockfile, or the OSV query failed |

`-fail kev` is the useful CI gate: it ignores severity entirely and fails only when something
in the tree is on CISA's known-exploited list.

## Directories skipped

`.git`, `node_modules`, `vendor`, `target`, `dist`, `build`, `.svelte-kit`, `.venv` — these
hold installed artefacts, and a vendored copy is not a declared dependency.

## Network

Three endpoints, all unauthenticated:

- `api.osv.dev` — required; the scan fails without it
- `raw.githubusercontent.com/cisagov/kev-data` — optional; CISA's own host 403s datacenter IPs
- `api.first.org/data/v1/epss` — optional

A missing optional feed degrades the ranking and prints a warning. It never fails the sweep.
