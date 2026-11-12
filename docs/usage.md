# Usage

## `douane scan [path]`

Reads every lockfile under `path`, resolves vulnerabilities, and prints them ranked.
Defaults to the current directory.

### Flags

| Flag | Values | Default | Effect |
|---|---|---|---|
| `-format` | `auto`, `text`, `line`, `json`, `sarif` | `auto` | Output shape |
| `-fail` | `never`, `any`, `low`, `medium`, `high`, `critical`, `kev` | `never` | Exit 1 at or above |
| `-scope` | `all`, `prod`, `dev` | `all` | Filter findings by how far they reach a runtime |
| `-informational` | `warn`, `fail`, `ignore` | `warn` | How to treat RUSTSEC informational defects |
| `-db` | path, or `""` | `~/.douane.db` | Sweep history; `""` disables it |
| `-no-enrich` | — | off | Skip the KEV and EPSS feeds |
| `-refresh` | — | off | Refetch the feeds, ignoring the cache |
| `-include-testdata` | — | off | Also read directories named `testdata`, which every walk skips by default |
| `-timeout` | a Go duration, such as `10m` or `90s` | `10m` | Stop the whole run after this long; requests that hit it become gaps |

The path may be given before or after the flags, so `douane scan -fail high /repos` and
`douane scan /repos -fail high` scan the same directory. A second path is a usage error.

`-fail any` fails on any finding at all, whatever its severity. Use it where the severity
axis is not the question, such as a repo you intend to keep at zero findings. `-fail kev`
is refused under `-no-enrich`, because with the KEV feed off every finding reads
not-exploited and the gate would pass having evaluated nothing.

`-informational` handles RUSTSEC's informational advisories — defects like "unmaintained" or
"unsound" that are not exploitable vulnerabilities. The default `warn` shows them as their own
tier but keeps them out of the exit code entirely, so an unmaintained crate no longer trips
`-fail any`. `fail` escalates them into the gate. `ignore` hides them from the report as well.
These carry no severity, so a `fail` without `-informational fail` is never their gate.

`douane --version` prints one line, `douane <version>`, and exits 0. The version is the
tag the binary was built from, or the commit when it was built from an untagged tree.

## `douane sweep [dir]`

Scans every repository directly under `dir` and reports across all of them, grouped by
repository and ranked globally. A directory counts as a repository when it holds a `.git`
or a lockfile at its top level; `sweep` does not recurse past that, so a monorepo is one
repository, not one per app.

Takes the same flags as `scan`. A repository with an unreadable lockfile or an invalid
`douane.yml` does not stop the others: it is reported, skipped, and counted in the summary. The sweep exits 3 under any
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

### Reading a sweep from a program

Read each repository's own `complete`, `failed` and `gaps`, never only its `findings`. The
union is resolved once, so a failed OSV query or a missing advisory record is a gap at the
root and also a gap on every repository it can have emptied: a failed query on every
repository with packages, a missing advisory on the repositories whose packages asked for
it. An outage therefore reads `"complete": false` on each affected repository, not as a
repository with no findings.

The exit code does not carry this under the default `-fail never`, which answers 0 whatever
the gaps (see below). A program that needs the exit code to say "incomplete" passes
`-fail any` and treats 3 as "retry", or reads the root `complete`.

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
and `gaps` are always arrays, so a consumer counts them without a null check. `permitted`
lists every finding a valid permit took out of `findings`, each with its `permit`, and a
finding a lapsed permit gave back carries `"expired_permit": true`. `out_of_scope_gaps`, present
only when there is one, lists the gaps `-scope` set aside.

**sarif** is SARIF 2.1.0, for code-scanning uploads such as `github/codeql-action/upload-sarif`.
One run, one rule per advisory id, one result per finding. A result's location is the lockfile
path with no region, because a dependency has no line. Its `partialFingerprints` carries
`primaryLocationLineHash` set to the finding's history key (`ecosystem|package|version|id`),
so the consumer does not derive one from lockfile lines and move the alert on every reformat.
Level follows severity: critical and high are `error`, medium is `warning`, low and unknown
are `note`. In a sweep, each path and fingerprint is prefixed with the repository name. Gaps
and warnings go to stderr, as in `line` and `json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clear, or findings below `-fail`, over a complete scan |
| 1 | Findings at or above `-fail`, or a finding whose permit has lapsed, whatever `-fail` says |
| 2 | Bad usage, a target douane cannot start from, or an invalid `douane.yml` on `scan` |
| 3 | Scan incomplete: douane could not determine part of the answer |

**3 is the one to read twice.** `-fail` is a claim about what was found, and douane can
only make that claim over a complete scan. So a run that hit an OSV error, an unparseable
lockfile or an ecosystem it cannot read exits 3 rather than 0, even when everything it did
manage to look at came back clean. CI can then tell "you are vulnerable", which is final,
from "I could not tell", which is worth one retry before it blocks.

Findings outrank incompleteness. A run holding both exits 1: both block, and "you are
vulnerable" is the finished answer, so there is nothing left to retry.

`-fail never` never returns 3. Gaps still print and still appear in the JSON, but "just
tell me what you found" is a valid request and douane answers it with 0. A program that runs
under `-fail never` must read `complete` and `gaps` itself, at the root or per repository.

`-fail kev` ignores severity entirely and fails only when something in the tree is on
CISA's known-exploited list. On this fleet it has never fired, so treat it as a tripwire
rather than a gate.

## Permits

`douane.yml` at the root of a scanned project suppresses findings until a date:

```yaml
permits:
  - id: GHSA-xxxx-xxxx-xxxx
    package: golang.org/x/crypto
    reason: no fix published, not reachable from the API
    expires: 2027-01-31
```

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | Any name of the advisory: CVE, GHSA or the ecosystem's own id |
| `package` | no | Narrows the match to one package |
| `reason` | yes | Why the finding is acceptable for now |
| `expires` | yes | `YYYY-MM-DD`, the last day the permit holds, at most 365 days ahead |

The file is a strict subset of YAML: a top-level `permits:` list of flat `key: value`
entries, values plain or quoted on one line, `#` comments allowed. `douane scan` exits 2 with the
path and line for a missing `id`, `reason` or `expires`, an unknown or repeated key, a date
that does not parse or lies more than 365 days ahead, or any YAML construct outside that
subset. It never skips an entry it cannot read, because a skipped permit is a finding its
author believes is handled.

| State | Output | Exit code |
|---|---|---|
| Valid | The finding leaves `findings` and every count, and appears under `permitted` in JSON | Not counted |
| Valid, with a gap of its own | The `severity`, `range` or EPSS-identifier gap the finding raised leaves `gaps` and is listed under the permitted finding's `gaps` | Not counted toward 3 |
| Lapsed | The finding stays, marked `EXPIRED PERMIT` in text, `permit=expired` in line, `expired_permit` in JSON | 1, whatever `-fail` says |
| Expires within 14 days | A note on stderr | Unchanged |
| Lapsed and suppressing nothing | A note on stderr asking to remove it | Unchanged |

A permit covers a gap only when every finding the gap concerns is permitted. The same unrated
advisory on a second package, or in a second repository of a sweep, that no permit names keeps
the gap and the exit 3. A gap about the scan itself, such as an unreadable lockfile, a feed
outage, an advisory record that never arrived or an invalid `douane.yml`, concerns no finding,
so no permit covers it.

### Gaps and `-scope`

`-scope` sets gaps aside the same way a permit does. A gap that concerns only findings the scope
filtered out, such as the `severity` gap of an advisory whose only finding is dev-only under
`-scope prod`, leaves `gaps`, no longer makes the run exit 3, and is listed under
`out_of_scope_gaps` in JSON: on the repository, and at the root for a fleet gap no repository
still holds in scope. A gap that also concerns a finding still in scope stays. A gap about the
scan itself concerns no finding, so `-scope` never removes it.

When two entries name the same finding, a valid one wins over a lapsed one, so a permit is
renewed by adding a fresh entry. Every permit note goes to stderr in every format, `text`
included. Permits apply after the history is recorded, so a permitted finding still counts
as seen and does not read as new on the day its permit lapses.

In a sweep, each repository reads its own `douane.yml` and nothing else. An invalid file costs
its own repository and nothing else. stderr names the file and line, the repository is
skipped with `"failed": true` and one `unreadable` gap whose `subject` is `douane.yml` and
whose `detail` carries the path and line, and every other repository is swept as usual. The
sweep then exits like any incomplete one: 3, unless findings at or above `-fail` make it 1,
and 0 under `-fail never`. The repository is skipped rather than scanned without its permits,
because that would report as held what its author believes is handled. A skipped repository
writes no history row, so its previous row stays the one the next run compares against and
its findings do not all read as new once the file is fixed.

```
douane: gap: app: unreadable: douane.yml: /src/app/douane.yml:2: permit is missing expires
```

## Gaps

A gap is one thing douane could not determine. It is what makes an incomplete scan visible:
the answer is not "no problem here", it is "no answer here", and the two must never render
the same way. Every gap carries a `kind`, the `subject` it is about, and a `detail` saying
what happened.

Six kinds, and what each one means when you find it in your output:

| Kind | What douane is telling you |
|---|---|
| `upstream` | An API refused, failed or truncated. The `subject` names the packages or the feed whose answer is missing. |
| `unreadable` | A lockfile douane recognises and could not parse, or, in a sweep, a `douane.yml` it refused. The `subject` is the file, relative to the scan root. |
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

### Gaps and the history

A gap that can hide findings still writes the history row for its repository: an `upstream` gap
from a failed OSV query, an `unreadable` or `unsupported` lockfile, an `unresolved` advisory or
package. The row holds every finding this run reported, plus every finding the previous row held
that this run did not report. douane cannot tell a finding that was fixed from one it could not
see, so it keeps both. The next run then marks NEW only what neither row held. A gap that cannot
hide a finding writes a plain row: `severity` and `range` qualify a finding that was reported, and
a KEV or EPSS feed outage or a Dockerfile build line douane could not read only leave a label off
one.

A gap that does not clear on a retry, such as an `unsupported` `pnpm-lock.yaml` beside a
`go.mod`, no longer freezes the history. The findings douane can scan are marked NEW once and
seen afterwards. A finding fixed while such a gap stands stays in the carried row, so it reads as
seen, not NEW, if it comes back before a complete run. The gap is still reported and still
counts toward exit 3.

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

`testdata` is skipped too, by the lockfile walk, the Dockerfile walk and sweep discovery
alike. Go leaves it out of every build, so a fixture there, such as a deliberately broken
`Dockerfile.bad`, is not something the project ships. `-include-testdata` reads it. The scan
root itself is always read, even when it is called `testdata`.

## Network

Three endpoints, all unauthenticated:

- `api.osv.dev` — required; the scan fails without it
- `raw.githubusercontent.com/cisagov/kev-data` — optional; CISA's own host 403s datacenter IPs
- `api.first.org/data/v1/epss` — optional

A missing optional feed degrades the ranking and prints a warning. It never fails the sweep.
