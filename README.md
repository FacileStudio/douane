# douane

Customs for your dependencies. `douane` reads a project's lockfiles, asks
[OSV.dev](https://osv.dev) what is vulnerable, ranks the result by whether anyone is
actually exploiting it, and prints only what is worth acting on.

```sh
douane scan ~/Code/Facile/Glure     # one project
douane sweep ~/Code/Facile          # every repository under a directory
```

```
CRITICAL  CVE-2026-9277 shell-quote@1.8.3  [NEW]
          epss 0.85% · fix 1.8.4 · npm · bun.lock
          shell-quote quote() does not escape newlines in object .op values

83 held out of 1204 packages
```

## Why it exists

`filet` is a pure function of your source tree. `douane` is a function of your source tree
**and today's date** — a repo you have not touched since March can become vulnerable tonight
because an advisory landed. That is why this is a separate binary with a separate trigger,
and why it keeps a history: the useful question is not "what is wrong" but "what is new".

Customs does not only inspect at the border. It also recalls goods that were cleared months
ago and have since been found dangerous. That is exactly the job.

## Install

```sh
git clone git@github.com:FacileStudio/douane.git && cd douane
mise run install          # GOBIN=$HOME/go/bin go install .
```

The repo is private, so `go install github.com/FacileStudio/douane@latest` needs
`GOPRIVATE=github.com/FacileStudio` and a working SSH remote. Cloning is simpler.

## Usage

```sh
douane scan  [path] [flags]   inspect one project
douane sweep [dir]  [flags]   inspect every repository under a directory

  -format auto|text|line|json   output shape (default auto)
  -fail   never|low|medium|high|critical|kev   exit 1 at or above (default never)
  -db     path to the sweep database (default ~/.douane.db, "" to disable)
  -no-enrich                    skip the KEV and EPSS feeds
  -refresh                      refetch the feeds, ignoring the cache
```

`sweep` takes the repositories directly under `dir`, resolves the **union** of their
packages in one pass, and hands the results back per repository. Sibling projects share
most of their dependency tree, so a fleet of 27 repos is far closer to one scan than to 27
— and the feeds are fetched once, not once per repo.

`-format auto` prints the human report on a terminal and the one-per-line form everywhere
else, so pipes and agent tool calls get the parseable version without asking.

Exit codes: `0` clear, `1` findings at or above `-fail`, `2` bad usage or unreadable input.

## How it ranks

CVSS alone produces hundreds of criticals and trains you to ignore all of them. douane sorts
by what predicts real harm:

1. **CISA KEV** — is this being exploited in the wild right now
2. **EPSS** — probability of exploitation in the next 30 days
3. **Severity** — how bad it would be if it happened

An empty `fixed_in` means **no fix exists on your branch**, which is a different decision
from a fix you have not taken yet. douane never conflates the two.

## Ecosystems

| Lockfile | Ecosystem |
|---|---|
| `go.mod` | Go |
| `package-lock.json` | npm |
| `bun.lock` | npm |
| `Cargo.lock` | crates.io |

`bun.lockb` is binary and cannot be read: douane **errors** rather than silently reporting
zero packages, because a false negative is the worst failure a scanner can have. In a sweep
the other repositories still complete, and the run exits 2. Run
`bun install --save-text-lockfile` to emit `bun.lock`.

## Known limitations

- **Go advisories usually carry no severity rating**, so Go findings often show `UNKNOWN`.
  Ranking degrades gracefully, since KEV and EPSS are consulted first.
- **No reachability analysis.** Every finding says `reachable: null`, meaning *unchecked* —
  never *unreachable*. `govulncheck` integration is the next milestone.
- **KEV carries this fleet no signal.** Zero of 732 findings across the suite are on the
  known-exploited list. It stays first in the ranking because one hit would matter, but do
  not expect it to fire.

See [ROADMAP.md](ROADMAP.md).

## Data handling

Findings are a live map of your attack surface. The sweep database, any inventory and any
suppression file are gitignored and must stay that way — including in fixtures and examples.
