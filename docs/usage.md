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
