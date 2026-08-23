# Usage

## `douane scan [path]`

Reads every lockfile under `path`, resolves vulnerabilities, and prints them ranked.
Defaults to the current directory.

### Flags

| Flag | Values | Default | Effect |
|---|---|---|---|
| `-format` | `auto`, `text`, `line`, `json` | `auto` | Output shape |
| `-fail` | `never`, `any`, `low`, `medium`, `high`, `critical`, `kev` | `never` | Exit 1 at or above |
| `-db` | path, or `""` | `~/.douane.db` | Sweep history; `""` disables it |
| `-no-enrich` | — | off | Skip the KEV and EPSS feeds |
| `-refresh` | — | off | Refetch the feeds, ignoring the cache |

The path may be given before or after the flags, so `douane scan -fail high /repos` and
`douane scan /repos -fail high` scan the same directory. A second path is a usage error.

`-fail any` fails on any finding at all, whatever its severity. Use it where the severity
axis is not the question, such as a repo you intend to keep at zero findings. `-fail kev`
is refused under `-no-enrich`, because with the KEV feed off every finding reads
not-exploited and the gate would pass having evaluated nothing.

`douane --version` prints one line, `douane <version>`, and exits 0. The version is the
tag the binary was built from, or the commit when it was built from an untagged tree.

## `douane sweep [dir]`

Scans every repository directly under `dir` and reports across all of them, grouped by
repository and ranked globally. A directory counts as a repository when it holds a `.git`
or a lockfile at its top level; `sweep` does not recurse past that, so a monorepo is one
repository, not one per app.

Takes the same flags as `scan`. A repository with an unreadable lockfile does not stop the
others: it is reported, skipped, and counted in the summary. The sweep exits 3 under any
`-fail` but `never`, because a repository that silently leaves the fleet is a false
negative, not a clean run.

```
GFConseil — 122 held out of 1065 packages

HIGH      CVE-2026-44578 next@16.0.10
          epss 38.87% · fix 16.2.5 · npm · bun.lock
          ...

  GFConseil    122 findings    1065 packages
  LauraHerve    92 findings     808 packages
  ...

1965 held out of 7517 packages across 29 repos — 1 clear
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

## Formats

`auto` resolves to `text` on a terminal and `line` everywhere else. Pass `-format text`
explicitly if you want the human report from a script.

**line** — one finding per line, greppable:

```
npm:shell-quote@1.8.3: critical: CVE-2026-9277 [bun.lock epss=0.0085 kev=false fix=1.8.4]
```

**json** carries the full report: `schema_version`, `complete`, the `gaps` array, and every finding
with its `key`, its `new` flag, `aliases`, the CVSS vector and the `exploit` block. `findings`
and `gaps` are always arrays, so a consumer counts them without a null check.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clear, or findings below `-fail`, over a complete scan |
| 1 | Findings at or above `-fail` |
| 2 | Bad usage, or a target douane cannot start from |
| 3 | Scan incomplete: douane could not determine part of the answer |

**3 is the one to read twice.** `-fail` is a claim about what was found, and douane can
only make that claim over a complete scan. So a run that hit an OSV error, an unparseable
lockfile or an ecosystem it cannot read exits 3 rather than 0, even when everything it did
manage to look at came back clean. CI can then tell "you are vulnerable", which is final,
from "I could not tell", which is worth one retry before it blocks.

Findings outrank incompleteness. A run holding both exits 1: both block, and "you are
vulnerable" is the finished answer, so there is nothing left to retry.

`-fail never` never returns 3. Gaps still print and still appear in the JSON, but "just
tell me what you found" is a valid request and douane answers it with 0.

`-fail kev` ignores severity entirely and fails only when something in the tree is on
CISA's known-exploited list. On this fleet it has never fired, so treat it as a tripwire
rather than a gate.

## Gaps

A gap is one thing douane could not determine. It is what makes an incomplete scan visible:
the answer is not "no problem here", it is "no answer here", and the two must never render
the same way. Every gap carries a `kind`, the `subject` it is about, and a `detail` saying
what happened.

Six kinds, and what each one means when you find it in your output:

| Kind | What douane is telling you |
|---|---|
| `upstream` | An API refused, failed or truncated. The `subject` names the packages or the feed whose answer is missing. |
| `unreadable` | A lockfile douane recognises and could not parse. The `subject` is the file, relative to the scan root. |
| `unsupported` | An ecosystem douane cannot read, such as `pnpm-lock.yaml`, or a project holding no lockfile it recognises at all. Those dependencies were never queried. |
| `unresolved` | OSV named a vulnerability id but its detail record never arrived, so douane knows a package is vulnerable and nothing else about the flaw. |
| `severity` | A finding whose severity could not be resolved, so it cannot be compared against a `-fail` threshold. |
| `range` | An advisory expressed as a commit range, which a lockfile recording a version cannot be checked against. |

Gaps print before the findings in every format, because a gap changes how the lines under it
should be read. `text` marks them with a question rather than a bang, since an unanswered
question is not a finding:

```
  ? unreadable: bun.lockb: binary bun lockfile is unreadable, run `bun install --save-text-lockfile` to emit bun.lock
```

`line` tags them so a grep can drop them, prefixed with the repository in a sweep:

```
douane: gap: binrepo: unreadable: bun.lockb: binary bun lockfile is unreadable, ...
```

`json` carries them as objects, and sets `complete` to false whenever `gaps` is not empty:

```json
{
  "kind": "unsupported",
  "subject": "pnpm-lock.yaml",
  "detail": "pnpm dependencies, an ecosystem douane cannot read"
}
```

An `unsupported` gap is the one to act on rather than retry: it will still be there tomorrow.
`upstream` is the one to retry. Both exit 3.

## Using douane in CI

The point of a separate exit 3 is that CI can retry it. Exit 1 is a finished answer and
should block; exit 3 means douane could not see everything, and a transient OSV error
clears on the second try.

```yaml
- name: Scan dependencies
  run: |
    code=0
    douane scan -fail high . || code=$?
    case "$code" in
      0) ;;
      1) echo "::error::vulnerable dependencies at or above high"; exit 1 ;;
      3) echo "::warning::douane could not complete the scan, retrying"
         douane scan -fail high . ;;
      *) exit "$code" ;;
    esac
```

`|| code=$?` is load-bearing: GitHub Actions runs `run:` blocks under `bash -e`, so without
it a non-zero exit kills the step before the `case` is reached. The retry is the last
command in the block, so a second 3 blocks the build, which is the intended behaviour: two
incomplete scans in a row is a problem, not a blip.

Two flags matter more in CI than locally. `-format line` is already the default off a
terminal, so no configuration is needed to get greppable output. `-db ""` disables the
sqlite history, which a fresh runner cannot carry between builds anyway, and with it the
feed cache; leave the database enabled if the runner has a cache directory that survives.

## Directories skipped

`.git`, `node_modules`, `vendor`, `target`, `dist`, `build`, `.svelte-kit`, `.venv` — these
hold installed artefacts, and a vendored copy is not a declared dependency.

## Network

Three endpoints, all unauthenticated:

- `api.osv.dev` — required; the scan fails without it
- `raw.githubusercontent.com/cisagov/kev-data` — optional; CISA's own host 403s datacenter IPs
- `api.first.org/data/v1/epss` — optional

A missing optional feed degrades the ranking and prints a warning. It never fails the sweep.
