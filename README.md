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
curl -fsSL https://raw.githubusercontent.com/FacileStudio/douane/main/install.sh | bash
```

That is a shim for `facile install douane`, the suite installer. On macOS,
Homebrew works too once the tap is populated:

```sh
brew install --cask facilestudio/tap/douane
```

From source, if you already have the checkout:

```sh
git clone git@github.com:FacileStudio/douane.git && cd douane
mise run install          # GOBIN=$HOME/go/bin go install .
```

## Usage

```sh
douane scan  [path] [flags]   inspect one project
douane sweep [dir]  [flags]   inspect every repository under a directory

  -format auto|text|line|json   output shape (default auto)
  -by     fix|finding           group by the fix that clears findings (default fix),
                                or print one block per finding
  -fail   never|any|low|medium|high|critical|kev
                                exit 1 at or above (default never)
  -db     path to the sweep database (default ~/.douane.db, "" to disable)
  -no-enrich                    skip the KEV and EPSS feeds
  -refresh                      refetch the feeds, ignoring the cache
  --version                     print the version and exit
```

`sweep` takes the repositories directly under `dir`, resolves the **union** of their
packages in one pass, and hands the results back per repository. Sibling projects share
most of their dependency tree, so a fleet of 27 repos is far closer to one scan than to 27
— and the feeds are fetched once, not once per repo.

`-format auto` prints the human report on a terminal and the one-per-line form everywhere
else, so pipes and agent tool calls get the parseable version without asking. The path may
be given before or after the flags.

`-by fix`, the default, prints one block per action that clears findings: take one package
to one target version. Two advisories against the same package at two installed versions are
one decision, so they print once with a count instead of twice. `-by finding` restores the
flat per-finding list. JSON always carries both shapes: `findings` untouched, plus a derived
`groups` array.

## Exit codes

```
0  clear
1  findings at or above -fail
2  bad usage or unreadable input
3  scan incomplete — douane could not determine part of the answer
```

`-fail` is a claim about what was found, and douane can only make that claim over a
complete scan. So anything it could not determine exits **3**, never 0: an OSV chunk that
came back an error, a lockfile it cannot parse, an ecosystem it cannot read. CI can then
tell "you are vulnerable" from "I could not tell" and retry the second before blocking on
it.

Findings still outrank incompleteness. A run that has both exits 1, because both block and
"you are vulnerable" is the finished answer. Under `-fail never` the gaps print and appear
in the JSON, but the exit stays 0: asking douane to just tell you is a valid request.

## How it ranks

CVSS alone produces hundreds of criticals and trains you to ignore all of them. douane sorts
by what predicts real harm:

1. **CISA KEV** — is this being exploited in the wild right now
2. **EPSS** — probability of exploitation in the next 30 days
3. **Severity** — how bad it would be if it happened

An empty `fixed_in` means **no fix exists on your branch**, which is a different decision
from a fix you have not taken yet. douane never conflates the two.

### Colour follows the ranking, not the severity

The same argument applies to colour, so severity is **not** what lights up. 91% of a real fleet
sweep is high or medium; painting those red reproduces in colour the exact failure the ranking
exists to avoid, and a screen that is entirely red ranks nothing.

What is coloured:

| | |
|---|---|
| red | `KEV`, `RANSOMWARE`, the known-exploited count |
| yellow | `NEW`, `NO FIX`, EPSS at or above 5%, gaps and warnings |
| green | the version that clears the finding, and `clear` |
| bold | the severity word, the package name, the repository name |
| dim | advisory ids, targets, ecosystems, prose |

So a healthy sweep is monochrome, and anything hot is worth the look.

Colour is on when the destination is a terminal and off otherwise, the same signal `-format
auto` already uses. `NO_COLOR=1` or `TERM=dumb` turns it off. **`line` and `json` are never
coloured, even on a terminal**, because they are the formats a pipe and an agent consume. The
decision is made per stream, so `douane sweep > report.txt` still colours the gaps on your
terminal while leaving the file plain.

## Ecosystems

| Lockfile | Ecosystem |
|---|---|
| `go.mod` | Go, and the Go standard library and toolchain from its `go` directive |
| `package-lock.json` | npm |
| `bun.lock` | npm |
| `Cargo.lock` | crates.io |

OSV publishes standard-library and `go` command flaws under two synthetic module names,
`stdlib` and `toolchain`, at the release the `go` directive names. They are the largest
source of advisories a Go repo has and they are declared nowhere else: `go 1.25.0` carries
46 stdlib and 11 toolchain advisories on its own. Across the suite that is 1308 findings
douane could not see at all, measured 2026-08-23.

`bun.lockb` is binary and cannot be read: douane **errors** rather than silently reporting
zero packages, because a false negative is the worst failure a scanner can have. In a sweep
the other repositories still complete, and the run exits 3. Run
`bun install --save-text-lockfile` to emit `bun.lock`.

## Known limitations

- **Go advisories carry no severity of their own.** A `GO-*` record holds neither a rating
  nor a CVSS vector; its GHSA twin holds both, and the alias link is the only way to reach
  it. douane resolves severity across the whole alias closure and takes the highest score in
  it, which costs extra requests to OSV. On 2026-08-23 that left 29 of the fleet's 1965
  findings reading `UNKNOWN`, from 8 advisories, and each of those raises a `severity` gap
  so it can no longer pass a threshold by being blank.
- **No reachability analysis.** Every finding says `reachable: null`, meaning *unchecked* —
  never *unreachable*. `govulncheck` integration is the next milestone.
- **KEV carries this fleet no signal.** On 2026-08-23 a sweep of 29 repos held 1965 findings
  and not one of them was on CISA's known-exploited list. KEV stays first in the ranking
  because a single hit would be an incident, but do not expect it to fire.

See [ROADMAP.md](ROADMAP.md).

## Data handling

Findings are a live map of your attack surface. The sweep database, any inventory and any
suppression file are gitignored and must stay that way — including in fixtures and examples.
