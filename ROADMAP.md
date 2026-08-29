# douane roadmap

The wiki holds the evidence (`~/.mycelium/memory/projects/douane.md`). This file holds the order.

Every milestone has an **exit criterion** — something verifiable, not a feeling. Milestone
numbers are stable identities, not a sequence: the order of work is stated once, below, and
changes as evidence arrives. Milestones that name no dependency can be built in parallel.

---

## The through-line

douane exists to answer one question: **what should I fix today?**

Every milestone is judged against that. A feature that adds findings without adding decisions is
a regression, however impressive the coverage number. The calibration target, inherited from
filet, is unforgiving:

> A sweep over a healthy suite prints **zero lines**.

We are **3816 findings** away from it, measured 2026-08-28 over the 65 working copies on lucy.
That gap is the roadmap, and the shape of it is now known rather than guessed:

| Cut | Findings | Where the work lives |
|---|---|---|
| ~~Go stdlib and toolchain~~ | ~~1879 (49%)~~ | **done 2026-08-29.** v1.8 reads the builder image; 787 are a rebuild |
| npm reachable only from `devDependencies` | 523 of 1371 classified (38%) | v2.3 |
| RUSTSEC informational, not vulnerabilities | 77 of 141 crates findings (55%) | v2.4 |
| Go dependencies that are not the toolchain | 124 | v2.1 |

Read that table before picking up any milestone. **Half of the number this roadmap is
calibrated against is one chore repeated 38 times, and douane has already answered it
correctly.** No feature clears those 1879 findings; a `go` directive does. Adding scanner
features to reduce a count that a dependency bump would reduce is the exact failure mode the
through-line exists to catch.

---

## v0 — shipped 2026-08-19

Lockfile → OSV.dev batch API → KEV + EPSS → sqlite history → ranked output.

Four ecosystems (`go.mod`, `package-lock.json`, `bun.lock`, `Cargo.lock`), one dependency beyond
stdlib, no scanner binaries, no vulnerability database to download.

`filet check` clean at default thresholds · `go test ./...` green · degrades to a warning when
either feed is unreachable · exit codes match filet's contract.

---

## v0.1 — the baseline, measured 2026-08-19

**732 findings · 230 unique advisories · 217 distinct (repo, package) bumps · 0 on KEV.**

Measured over all 27 repos in `~/Code/Facile` from ruche. Split npm 623 / Go 109. Severity:
347 medium, 231 high, 74 low, 43 unknown (all Go), 37 critical. Only **18 findings have no fix**,
and 16 of those are one unfixed advisory — `GO-2026-5932` in `golang.org/x/crypto`, present at
0.31, 0.42 **and** 0.54, so upgrading does not clear it. Worst repos: GFConseil 122,
LauraHerve 92, Glouton 83, Glure 83, Nook 79. Every Go service sits in the 10–40 band, almost
entirely transitive.

Full numbers live in the wiki. They are a map of the attack surface and stay out of this repo.

### What the baseline changed

**KEV is silent, and probably always will be.** Zero hits out of 732. The catalogue is ~1670
CVEs weighted to enterprise edge appliances; a fleet of Go services and Svelte apps does not
appear in it. KEV stays in the ranking because a single hit would be an incident, but it can no
longer be the headline prioritiser or a CI gate we rely on.

**EPSS is quiet too.** Two findings above 5% — `next` CVE-2026-44578 at 38.9% (GFConseil) and
`lodash` CVE-2021-23337 at 21.3% (LauraHerve) — then a cliff to under 3.5%. Real signal, thin.

**So "is it actually deployed" is now the first prioritiser, not the third.** It is the only
axis left that separates 732 findings into different decisions. v3 moves up accordingly.

**97.5% of findings are a version bump, and 732 findings are 217 bumps.** Grouping the report
by fix rather than by finding is a 3.4× reduction with no judgment involved. That belongs in the
binary, not only in the skill — hence the new v1.4.

**Suppressions cannot carry this alone.** A permit file that got 732 findings to zero lines
would be a 700-line dated to-do list, which is exactly the artefact the data-handling rule
warns about. Reachability and deployment do the cutting; permits handle the residue. v1.1 is
still necessary and no longer urgent.

---

## v0.2 — the baseline remeasured, 2026-08-28

**3816 findings · 463 distinct advisories · 315 fleet fix groups · 250 (repo, package) bumps ·
0 on KEV.**

Measured on **lucy** over the 65 working copies in `~/Projects/Facile/Code`, enriched, 32s warm,
`douane 0.2.2`. Ecosystems: Go 2003, npm 1672, crates.io 141. Severity: 1707 medium, 1632 high,
218 low, 136 critical, 123 unknown. 87 findings have no fix. 45 gaps: 43 severity, 2 unsupported.
Five repos already print zero lines: `ardoise-cli`, `authentik-config`, `croc`, `perception-js`,
`portail`.

### Every previous number in this file was measured on less than half the fleet

ruche holds **30** directories under `~/Code/Facile`. lucy holds **65**. The 732-finding and
1965-finding baselines were taken on ruche, so they were never fleet-wide, and the jump to 3816
is mostly that, not a new class of finding. ruche also has **no Go toolchain, no `govulncheck`
and no `douane` binary** installed today, though `~/.douane.db` is there. This settles the "where
does the sweep run" open decision below and adds prerequisites to v5.1.

### The decision count did not move when the fleet doubled

29 repos produced 315 fix groups on 2026-08-24. 65 repos produce **315** fix groups today.
Findings went from 1965 to 3816 and the number of distinct decisions stayed flat, because
sibling repos share their dependency trees. That is the tool's whole thesis, measured. It also
means **per-repo finding counts are the wrong headline** and the fleet group count is the right
one.

### EPSS is no longer thin, and the stdlib is why

The v0.1 baseline saw two findings above 5% and a cliff. Today: **16 above 5%, 14 above 10%, and
one at 92%**, which is `CVE-2023-45288` in the Go `stdlib`, in `backend-protobuf-poc`. The single
sharpest finding in the fleet came from the coverage v1.5 added, and it sits in a proof of
concept that is almost certainly not deployed. That is v3's argument in one line.

### KEV is silent for the third time

Zero hits out of 3816, enriched. Two prior measurements at 732 and 1965 said the same. Treat
`-fail kev` as a tripwire that has never fired, never as the gate.

### Two correctness defects that a bigger fleet made visible

**11 findings are reported under an advisory id that exists nowhere.** The first count filed
here was 541 across 45 repos, and it was wrong: it counted every primary id OSV answers 404 for,
but 25 of those 27 ids are CVEs that resolve perfectly well at nvd.nist.gov, checked 2026-08-29.
Absent from OSV is not the same as unlookupable. Only two ids are genuinely broken, both GHSAs
that 404 on OSV **and** on github.com/advisories, and they cover 11 findings.

The cause is real either way: `Canonical` in `internal/osv/resolve.go` ranked CVE > GHSA > rest
and took the winner out of the alias list without checking it resolves. The lesson is in the
correction, not the bug. Narrowing the rule to ids **proven absent**, rather than ids douane
does not happen to hold, is what kept the fix from demoting almost every npm finding to its
GHSA and rewriting the history the store keys on that id. Fixed 2026-08-29.

**All 43 severity gaps now have a cause, and only 3 are irreducible.** Probing every gap subject
against OSV: **32 are RUSTSEC informational advisories** (26 unmaintained, 6 unsound) that carry
no severity by design and should never have been gaps at all, **8 are the unresolvable ids
above**, and **3 are genuinely unrated** (`GO-2026-5932`, `RUSTSEC-2026-0204`,
`RUSTSEC-2026-0235`). So v2.4 clears 32, v1.6 clears 8, and the honest residue is 3. Neither
milestone needs to touch `internal/osv/severity.go`, which is doing its job.

**A withdrawn advisory is reported as live.** `osv.Vuln` has no `withdrawn` field, so the schema's
own retraction marker is invisible. Measured: `CVE-2024-24788`, withdrawn 2025-02-28, still
reported against `backend-protobuf-poc`. One finding today, and no upper bound on tomorrow. v1.6.

### Two ecosystems are unreadable, and one of them is a flagship

`Opus` ships `pnpm-lock.yaml` and `Echo` ships `services/transcriber/requirements.txt`. Both
raise an honest `unsupported` gap, so nothing is silently green, but Opus is a full product and
douane can see none of it. v1.7.

---

## Order of work

Evidence, not milestone numbers, sets this. Reordered 2026-08-28 against the v0.2 baseline:

1. ~~**v1.8** toolchain resolution~~ and ~~**v1.9** release-line collapse~~, shipped 2026-08-29
2. ~~**v1.2** feed caching~~, shipped 2026-08-19
2. ~~**v1.3** `douane sweep`~~, shipped 2026-08-19
3. ~~**v1.5** gaps and the incomplete-scan contract~~, shipped 2026-08-23
4. ~~**v2.2** severity from the alias closure~~, shipped 2026-08-23
5. ~~**v1.4** report by fix~~, shipped 2026-08-24
6. **The Go directive chore.** Not a milestone and not douane's code. 1879 findings, 38 repos,
   one line each. Do it first so every number below is measured against a fleet that is not
   half noise.
7. ~~**v1.6** withdrawn and unresolvable ids~~, shipped 2026-08-29 alongside v1.8.
8. **v2.3** dev-only dependencies. 523 findings, computable offline from the lockfile already
   parsed, no new feed and no new binary. Now the largest cut douane itself can make.
9. **v2.4** informational advisories. 77 findings, one field.
10. **v5.1** the nightly daemon. The trigger the tool was built for, and the only one that
    matches how the answer changes. Do it once the count is survivable, not before.
11. **v3** deployed-or-not. Still the sharpest judgment axis, and now the one that separates the
    92% EPSS finding in a PoC from the same finding in production.
12. **v1.1** permits, then **v5.3** the introduced-finding gate. A repo cannot go green honestly
    without permits, and CI cannot gate on anything until it can.
13. **v2.1** govulncheck, **demoted**. After the chore its addressable set is 124 findings, not
    2003. Still the only reachability there is, but it is no longer the headline.
14. **v1.7** pnpm and pip, **v4** Dependabot, **v5.2** the skill.

### Why v2.1 fell from first to thirteenth

The v0.1 baseline framed reachability as the answer to a Go-heavy fleet, and v1.5 seemed to
confirm it by taking Go from 109 findings to 2003. But 1879 of those 2003 are the standard
library and toolchain, spread over 10 distinct `go` directives from 1.22 to 1.26.5, and the fix
for every one of them is the same patch bump. Reachability earns its cost where the fix is
expensive or absent. Here the fix is one line, in a file that is already being edited, so
knowing which of the 1879 are reachable changes no decision.

What is left afterwards is 124 Go dependency findings, which is the set v2.1 should be sized
and judged against.

---

## v1 — make the fleet scannable

### v1.2 Feed caching — shipped 2026-08-19

**Why.** Every run refetches the whole KEV catalogue (1670 entries) and re-queries EPSS. The
v0.1 baseline downloaded KEV **27 times** in one sitting. It is also what makes douane useless
on a plane.

**What.** Cache both feeds in the sweep database with a 24h TTL. KEV is one blob, so it is cached
whole; EPSS is queried per CVE, so it is cached per CVE and only the missing ones are fetched.
`-refresh` forces a fetch. A stale cache is used with a warning when the network fails.

**Note.** There is no `feed_cache` table today — earlier drafts of this file claimed there was.
`internal/store/store.go` holds `sweeps` and `findings` only. Both cache tables are new.

**Exit criterion, met.** Second run within the TTL makes zero requests to KEV or EPSS
(`feed_cache.fetched` is unchanged; `-refresh` moves it). With the network down and a warm
cache, ranking is still fully populated and one warning names the cache age. A KEV payload
with zero entries is refused rather than cached.

**Depends on.** Nothing.

### v1.3 `douane sweep` — shipped 2026-08-19

**Why.** douane is a per-repo tool and the reason it exists is the fleet. The v0.1 baseline was a
shell `for` loop, which is this command with none of the reporting and 27× the network.

**What.** `douane sweep [dir]` discovers the repos directly under `dir`, collects every
inventory, **unions the packages and resolves once** — Glure and Glouton alone share ~1000
packages, and 732 findings across the suite are 230 advisories — then splits the results back
per repo. Grouped by repo, ranked globally, same history diff, one summary row per repo.

**Exit criterion, met.** `douane sweep ~/Code/Facile` completes in **13s** warm (the shell
loop it replaces took ~2min) and reproduces the v0.1 total of 732 findings across 27 repos.
A second run reports zero `[NEW]`.

**Depends on.** v1.2 — without caching this is 27 KEV downloads.

### v1.5 Gaps and the incomplete-scan contract, shipped 2026-08-23

**Why.** douane had no way to say "I could not determine this", so every path where the scan
came up short rendered as a clean exit. Eight were proven against the live API: OSV's error
envelope decoding to zero results, a batch response shorter than the request, a failed detail
fetch dropping its finding, a repo with no recognised lockfile vanishing from the sweep, a path
after the flags being ignored so douane scanned `$PWD`, `SevUnknown` sitting below every `-fail`
threshold, `next_page_token` ignored, and the `go` directive discarded so no Go repo was ever
checked against the standard library it ships.

**What.** One structured record, `finding.Gap`, replacing three incoherent ways of saying
something went wrong: a warning string with no effect on the exit code, a `Failed` bool set in
exactly one place, and findings simply being absent. Six kinds, each carrying its subject and
what happened: `upstream`, `unreadable`, `unsupported`, `unresolved`, `severity`, `range`.
Exit code **3** for a scan carrying any gap under a `-fail` other than `never`, so CI can tell
"you are vulnerable" from "I could not tell". Plus `-fail any`, `--version`, `stdlib` and
`toolchain` from the `go` directive, one HTTP client with status checks and bounded retry behind
all three feeds, and the sqlite DSN that stops concurrent sweeps going busy.

**Exit criterion, met.** A scan of a directory whose only lockfile is `pnpm-lock.yaml` exits 3
under `-fail low` and 0 under `-fail never`, reporting an `unsupported` gap either way. A sweep
whose only repo carries a `bun.lockb` still lists that repo and exits 3. A run holding both
findings above the threshold and a gap exits 1. `douane scan .` on this repo reports the 46
`stdlib` and 11 `toolchain` advisories of `go 1.25.0`, where the previous binary reported none.
The suite sweep reports 29 repos including `hooks`, which declares no dependencies at all and
used to vanish. `douane --version` prints one line.

**Depends on.** Nothing.

### v1.4 Report by fix, not by finding — DONE 2026-08-24

**Why.** 732 findings are 217 bumps and 230 advisories. The same `x/crypto` line appears in 16
repos and the same `hono` advisory 67 times. Printing per finding is printing the same decision
dozens of times, and it is the single largest source of noise measured so far.

**What shipped.** Default output (text, line, single scan and sweep) groups findings by the
action that clears them: one block per `(ecosystem, package, target version)` carrying count,
worst member under the rank ordering, ids, installed versions and affected targets.
`-by finding` restores the flat list byte-for-byte. JSON carries both shapes: `findings`
untouched, plus a derived `groups` array. Grouped sweep output still names repos that left
gaps, so grouping cannot manufacture certainty. `finding.Group` lives in
`internal/finding/group.go`; `Severity` gained the `UnmarshalJSON` half its `MarshalJSON`
was missing.

**Exit criterion.** Met by construction: groups derive from the full finding list and json
keeps both shapes. Measured on the suite 2026-08-24: `sweep` prints 315 primary lines where
the flat form prints 3938; the fleet outgrew the 732-finding baseline this item was sized
against, so ≤250 no longer applies as written.

**Depends on.** Nothing. Sharper after v1.3.

### v1.1 Permits (suppressions with mandatory expiry)

**Why.** Without suppression the output never shrinks and stops being read. With unbounded
suppression, findings vanish permanently and the tool lies. The name already settled this: a
suppression is a **temporary permit**, and permits expire. Demoted from first to sixth by the
baseline — at 732 findings the permit file would be the bigger liability.

**What.** `douane.yml` in the repo. Each entry requires an `expires:` date and a `reason:`, both
rejected at parse time if missing. douane **fails loudly** when a permit lapses rather than
silently reinstating the finding, and lists permits expiring within 14 days on every run.

**Exit criterion.** A suppressed finding disappears from output; the same finding reappears with
an `EXPIRED PERMIT` marker once its date passes; an entry missing `expires:` exits 2 with a
message naming the line.

**Depends on.** Nothing.

### v1.6 Withdrawn advisories, and ids that do not resolve, shipped 2026-08-29

**Why.** Two defects found in the v0.2 baseline, both in identity handling, both silent.

`Canonical` (`internal/osv/resolve.go`) reports a finding under the highest-ranked id it can find
in `{v.ID} ∪ v.Aliases`, CVE over GHSA over the rest, without checking that the winner exists in
OSV. First measured as **541 findings across 45 repos** under 27 distinct ids, which overstated
it: 25 of those ids are CVEs that resolve at nvd.nist.gov, so they are poor keys for a
round-trip and fine keys for a human. The real defect is the 11 findings under a GHSA that
`GET /v1/vulns/<id>` answers 404 for. `github.com/klauspost/compress@1.17.11` is reported as
`GHSA-259r-337f-4rfw`, which 404s, while `GO-2026-5841`, which OSV returned and which resolves,
sits in `aliases`. `h2` is reported as `GHSA-q83h-524g-xf6h` in 8 repos, same story, with
`RUSTSEC-2026-0258` demoted. The closure then tries to fetch the promoted id to rate it, fails,
and the finding lands UNKNOWN with a `GapSeverity`. That accounts for **8 of the 43 severity
gaps**; the other 35 are v2.4's problem and 3 genuinely have no rating anywhere.

The second is plainer: the OSV schema has a `withdrawn` timestamp and `osv.Vuln` has no field for
it, so a retracted record is reported as a live vulnerability. Measured: `CVE-2024-24788`,
withdrawn 2025-02-28, still reported.

Preferring the CVE is not itself wrong. A CVE is the cross-ecosystem name and it resolves at
nvd.nist.gov whether or not OSV carries a record. What is wrong is printing an identifier as a
finding's primary key when the database it came from cannot answer for it, because that key is
what a permit file (v1.1), the skill (v5.2) and any human follow-up all key on.

**What.** `Withdrawn string` on `Vuln`, and a withdrawn record is dropped before it becomes a
finding, not filtered at render. `Canonical` keeps its CVE preference but the promoted id must be
one douane holds a record for; otherwise the id OSV returned stays primary and the CVE goes in
`aliases` where it is still printed and still searchable. A negative fetch is cached for the feed
TTL so 27 ids are not re-requested on every sweep.

**Exit criterion.** Every `id` in `douane sweep -format json` answers 200 from
`GET https://api.osv.dev/v1/vulns/<id>`, verified by probing the distinct set. No finding carries
a `withdrawn` record. Severity gaps drop by 8 with no change to `internal/osv/severity.go`.

**Depends on.** Nothing. Sharpens v1.1, v5.2 and v5.3, all of which key on the id.

### v1.8 The toolchain that builds the binary, shipped 2026-08-29

**Why.** The `go` directive is a floor, not the version that ships. Since Go 1.21 the toolchain
used is whichever is installed if newer, and every containerised app here builds from a floating
`golang:1.25` tag resolving to the newest patch. douane read the floor and reported it as the
shipped version, so half the fleet's findings described a binary nobody runs.

**What shipped.** `inventory.BuildLines` reads which module each Dockerfile stage actually
builds, from the `COPY <path>/go.mod` line inside a `FROM golang` stage. Per module, never per
repo: Journal has three modules, a root Dockerfile building `apps/api`, a second under
`apps/collector`, and `sdk/journal` built by neither because it is a library shipped as source.
A repo-wide heuristic would have told that library's consumers their compiler was patched.

Findings whose fix lands on the line the image already builds from are labelled `REBUILD`. The
label never suppresses: whether the image has been rebuilt since the advisory landed is a
question douane cannot answer, so `-fail` still counts them.

**Exit criterion, met.** Registre 12 fixes to 5, 37 of its 40 findings marked rebuild, leaving 3
real. Journal 39 to 13. The fleet 315 distinct actions to 195, with 787 findings cleared by a
rebuild. `sdk/journal` correctly carries none.

**Depends on.** Nothing.

### v1.9 Collapse a release line, shipped 2026-08-29

**Why.** A linearly versioned package broke the one-group-per-decision premise that v1.4 exists
for. On Registre the Go `stdlib` alone produced six groups at `1.25.8` through `1.25.13`, when
`1.25.13` clears all six.

**What shipped.** Groups fold within a release line, keeping the highest patch. Only within one:
a repo with modules on `go 1.24` and `go 1.25` carries targets on both lines at once, and merging
them would sell a minor upgrade as a patch bump.

Rebuild-ness is part of the group key rather than a label applied afterwards. Journal put 46
findings cleared by rebuilding and 29 needing a real bump into one collapsed group, both at
`1.25.13`, because they came from different modules. A group is named by what clears it, so
labelling that group either way hid half of it. **A grouping rule that can mix two actions is a
false negative waiting for a fleet big enough to show it.**

**Exit criterion, met.** Six same-line targets collapse to one; the two-line case stays two; the
same target version under different build situations stays two.

**Depends on.** v1.4.

### v1.7 pnpm and pip

**Why.** `Opus` is a full self-hosted product and douane reads none of it, because it is the
suite's one pnpm monorepo. `Echo` ships a Python `requirements.txt` for its transcriber service.
Both currently raise an `unsupported` gap, which is the honest answer and not a useful one.

The blast radius is exactly two repos today, which is why this sits low. It moves up the moment
a third arrives, and `pnpm-lock.yaml` is the one to build first: it is a lockfile with a resolved
package list, where `requirements.txt` is frequently unpinned and may not answer at all.

**What.** A parser per format behind the existing inventory interface. `pnpm-lock.yaml` v6 and v9
`packages`/`snapshots` keys to npm ecosystem entries. `requirements.txt` only for lines pinned
with `==`; anything looser raises an `unresolved` gap rather than guessing a version.

**Exit criterion.** `douane scan` on Opus reports npm findings and no `unsupported` gap. An
unpinned `requirements.txt` line produces a named gap, never a silent omission and never an
assumed version.

**Depends on.** Nothing.

---

## v2 — cut the noise

### v2.1 govulncheck adapter (reachability), demoted 2026-08-28

**Why.** The one genuinely irreplaceable tool in the space. Call-graph analysis reports a Go CVE
only if your code can reach the vulnerable function. `Finding.Exploit.Reachable` is already a
`*bool` waiting for it: `nil` means unchecked, and must never be conflated with `false`.

**Why it dropped to thirteenth.** This was sized against 2003 Go findings. 1879 of those are the
standard library and toolchain, and their fix is a `go` directive bump the repo wants anyway, so
reachability changes no decision there. The honest addressable set is **124 Go dependency
findings**, still mostly transitive `x/crypto` and `x/oauth2`, which is the shape reachability
deletes but a tenth of the prize this milestone was written for.

**What.** A `Scanner` interface with `govulncheck` as its second implementation, invoked when a
`go.mod` is present and the binary is on PATH. Absent binary degrades to `nil`, never to `false`.

**Exit criterion.** The **non-stdlib** Go finding count drops measurably against the 124 baseline,
and every surviving Go dependency finding reports `reachable: true`. Stdlib findings are excluded
from the measurement, not from the scan.

**Depends on.** The Go directive chore, so the 124 is what gets measured. Needs a Go toolchain and
`govulncheck` wherever the sweep runs; ruche has neither today.

### v2.3 Dev-only dependencies

**Why.** After the Go chore, npm is the fleet at 1672 findings, and reachability in the
govulncheck sense does not exist for it. The axis that does exist is in the lockfile already:
a package reachable only from `devDependencies` ships in nobody's runtime. A vulnerable `esbuild`
that builds the bundle is a different decision from a vulnerable `hono` that serves requests, and
douane currently prints them identically.

Measured on the v0.2 baseline by walking the graph offline. Of the 1404 npm findings in repos
carrying a `bun.lock`, 1371 classify: **848 reachable from `dependencies`, 523 reachable only
from `devDependencies`**. 38%, for one graph walk over a file douane already parses. The
remaining 33 did not resolve to a lockfile key and the other 268 npm findings are in
`package-lock.json` repos this walk did not cover. Worst offenders are the ones the fleet forks
from: MonorepoBoilerplate 117, GFConseil 78, LPB 68, Heranova 53, Ardoise 50.

Treat 38% as the order of magnitude, not the target. It is one prototype walk, and the
milestone's own exit criterion is what settles the real number.

**What.** Resolve each npm package to `prod`, `dev` or `both` and carry it on the finding.
`bun.lock` gives the direct kinds per workspace and each `packages` entry carries its own
dependencies, so the closure is computable with no network. `package-lock.json` states it
outright with `"dev": true`. A package reachable both ways is `prod`; dev-only is a claim that
needs the whole graph to hold, so it is never inferred from the direct list alone. Unresolvable
attribution raises a gap and is treated as `prod`, because guessing wrong in that direction is
the one that hides a real finding.

`-scope prod|dev|all` filters, defaulting to `all` so the number never shrinks silently. The
ranking demotes `dev` below `prod` at equal severity from day one, which is where most of the
value is even before anyone passes a flag.

**Exit criterion.** Every npm finding carries `scope`, `douane sweep -scope prod` returns a
strictly smaller set than `-scope all`, and a package pulled in by both a runtime and a build
dependency reports `prod`. Spot-check three findings against `bun pm ls --all` in the repo they
came from.

**Depends on.** Nothing. Cheaper and larger than v2.1; do it first.

### v2.4 Informational advisories are not vulnerabilities

**Why.** RUSTSEC publishes maintenance notices through the same channel as vulnerabilities.
`derivative is unmaintained` is a real thing to know and it is not a thing to fix tonight, and
douane currently prints it beside a memory-safety bug with the same weight. They also arrive
with no severity and no patched version by construction, which is why they dominate both the
UNKNOWN bucket and the no-fix bucket and make both look worse than they are.

Measured: **77 of 141 crates.io findings are informational**, being 61 `unmaintained`, 16
`unsound` and 0 `notice`. Only 64 crates findings are actual vulnerabilities, and only 2 of those
have no fix, against the 64 that appeared to.

The marker is at `affected[].database_specific.informational`, not top level. A top-level
`database_specific` read finds only `{"license": "CC0-1.0"}`, which is how this was missed.

**Prior art, and the reason not to just drop them.** cargo-audit separates the two: informational
advisories are **warnings**, not vulnerabilities, and `cargo-audit/src/config.rs` defaults
`informational_warnings` to all three kinds while `--deny unmaintained` escalates on request.
That is the right shape. `unsound` in particular is often a genuine memory-safety hazard wearing
an informational label, so silently discarding it would be a false negative dressed as a noise cut.

**What.** Read the marker, carry it on the finding, rank informational below every rated
vulnerability, and exclude it from `-fail` unless asked. `-informational warn|fail|ignore`,
defaulting to `warn`. An informational advisory no longer raises a `GapSeverity`, because
"no severity" is the correct and complete answer for it rather than something douane failed
to determine.

**Exit criterion.** `douane scan` on a Rust repo separates informational from vulnerabilities in
the output, `-fail high` no longer trips on an unmaintained crate, `-informational fail` still
trips, and the fleet severity gap count drops by 32, from 43 to 11.

**Depends on.** Nothing. Overlaps v1.6: both are gaps that are not really gaps.

### v2.2 Severity for Go advisories, shipped 2026-08-23

**Why.** `GO-*` records omit `database_specific.severity`, so 46 findings read `UNKNOWN` on
2026-08-23, all of them Go. With KEV silent and EPSS thin, severity is doing more ranking work
than the original design assumed, and it is blank exactly where the fleet's own code lives.

**The premise this milestone rested on was false.** It said "compute the CVSS v3 base score from
the vector already present in `severity[]`". The vector is not present. Measured 2026-08-23:
0 of the 46 UNKNOWN findings carry one, and `GO-2026-5932` answers with `severity: None` and a
`database_specific` block holding a URL and a review status, nothing else.

**What.** The rating lives on the advisory's GHSA twin and is reachable only through the alias
link, because the CVE record that carries the vector often has an empty `affected[]` and no
package query can return it. So: build the alias closure from the records OSV returned, fetch the
members not already held, and take the highest CVSS across the closure. Not first-wins:
`CVE-2025-22870` has `severity: null` while its GHSA sibling carries the vector. osv-scanner does
the same and never reads `database_specific.severity` at all.

**Exit criterion, met.** A fleet sweep on 2026-08-23 holds 29 UNKNOWN findings, down from 46,
and the finding count tripled in the same pass. The residue is 8 `GO-*` advisories, each raising
a `severity` gap that names itself, so none of them can pass a threshold by being blank. A scan
of this repo reports 29 HIGH, 24 MEDIUM, 3 CRITICAL and 1 LOW where all 57 of its findings
previously read UNKNOWN.

**Depends on.** Nothing.

---

## v3 — is it actually deployed?  *(promoted)*

**Why.** A CVE in a repo last deployed in March is a chore. The same CVE in the container serving
production is an incident. With KEV at zero for the third measurement, this is the sharpest
remaining judgment axis, and nothing else in the stack can make the distinction.

The v0.2 baseline handed this milestone its argument in one finding. `CVE-2023-45288` in the Go
`stdlib` scores **0.9197 on EPSS**, the highest in the fleet by a factor of two and the only
finding above 50%. It is in `backend-protobuf-poc`. Whether that is the most urgent thing douane
has ever printed or entirely ignorable is decided by one fact douane does not have, and the same
question applies to the other 15 findings above 5%.

Note what this does to the earlier "EPSS is thin" conclusion: it was thin because the scan was
missing the standard library. With that coverage in, EPSS separates 16 findings from 3800, which
is exactly the job. It is a genuine prioritiser again, and it hands its top result straight to
this milestone.

**What.** `trivy image` (not grype — they overlap ~90%, pick one) against the images Dokploy
reports as running on ruche, correlated back to findings. Trivy runs via `docker run` with a
cached DB volume, so nothing new lands on PATH.

**Exit criterion.** Findings carry a `deployed` flag sourced from the Dokploy API, and
`douane sweep --deployed-only` returns a strictly smaller set.

**Depends on.** v1.3.

---

## v4 — the Dependabot collector

**Why.** GitHub is very likely already raising alerts on these repos and nobody has ever opened
the tab. Pure read, no scanning, cheap — and comparing its list against our 230 advisories is
free intelligence about both sources' false-positive rates.

**What.** `douane alerts` over `gh api /repos/FacileStudio/<repo>/dependabot/alerts`, merged into
the same `Finding` shape and deduped on the alias graph alongside OSV results. `Sources` gains a
second entry.

**Exit criterion.** One command lists every open Dependabot alert across the suite, and findings
seen by both sources report `sources: ["osv", "dependabot"]`.

**Depends on.** Nothing.

---

## v5 — automation

### v5.1 The nightly daemon

**Why.** douane's verdict changes when the world changes, not when you commit. A scanner you must
remember to run reports on your last panic, not your current risk.

**What.** A mycelium flow on ruche running `douane sweep` nightly, diffing against sqlite, alerting
through **antenne** only on what is new or newly escalated. Given the baseline, the alert
threshold is "new since yesterday", never the standing total.

**Exit criterion.** A quiet night produces no alert at all. A newly published advisory affecting
a deployed service produces exactly one.

**Depends on.** v1.2, v1.3, and enough of v1.4/v2.3/v2.4/v3 that a nightly alert is readable.

**Prerequisites on the host, measured 2026-08-28.** ruche has `~/.douane.db` and **no `douane`
binary**, so the flow installs one. It has **no Go toolchain**, which also blocks v2.1 there. And
it holds 30 repo directories against lucy's 65, so a nightly sweep on ruche as it stands would
report a clean fleet while covering under half of it. That is the exact failure the exit criterion
above cannot detect, since a repo that is absent produces no alert and a quiet night produces no
alert. Add a coverage assertion: the flow fails loudly if it sweeps fewer repositories than the
last run, rather than reporting silence.

### v5.2 The `/douane` skill

**Why.** The binary must never call a model — it stays deterministic, offline-capable and
key-free. The judgment lives in a skill, exactly as `filet` splits it.

**What.** Runs `douane scan -format json`, triages, and reports **by fix rather than by finding**
before touching anything. Fixes causes, then runs the project's tests. Two hard rules: never bump
a lockfile without running the tests, and never add a permit to make the output green. Escalates
to `/facile-plan` when the fix is architectural — which is what an empty `fixed_in` usually
means, and the baseline says that is 18 findings, 16 of them the same one.

**Exit criterion.** The skill fixes a real finding in a suite repo, the tests pass, and it reports
honestly what it left behind and why.

**Depends on.** v1.1 (it needs somewhere legitimate to defer a finding), v1.4 (the grouping it
reports is better computed once, in the binary), v1.6 (it keys on ids, and 14% of them do not
resolve), and a stable JSON shape.

### v5.3 The introduced-finding gate

**Why.** The obvious next step after a working scanner is a hook or a CI job, and both are wrong
today for different reasons.

A git hook is wrong permanently. douane's answer is a function of the source tree **and today's
date**. A hook fires on the one event that does not change the answer, your commit, and stays
silent on the one that does, an advisory published overnight. That is the whole reason this is a
separate binary from `filet` with a separate trigger, and it is why v5.1 is the real answer.

CI is right eventually and wrong now. `-fail` is evaluated over the entire finding list
(`shouldFail`, `internal/cli/history.go`), so it is a claim about the repo's **state**. Turned on
today at `-fail high` it fails **57 of the 65 repos** on the first push, for findings nobody in
that pull request introduced, which trains everyone to append `|| true` inside a week.
The gate that would work asks a different question: did **this change** introduce a finding.

douane cannot express that. `[NEW]` exists but comes from `st.PreviousKeys(report.Target)` against
`~/.douane.db`, keyed on the local path. A CI runner is ephemeral, so the database is absent and
every finding is new; a shared runner has one, but keyed wrongly. There is no committed baseline
and no way to diff against a merge base.

**What.** A baseline douane can be handed rather than one it must remember. `douane scan
-baseline <file>` compares against a committed or artifact-stored finding set and `-fail` applies
only to findings absent from it, with `-fail-total` keeping today's state-based behaviour for the
nightly. The baseline is keyed on `Finding.Key()`, which already exists and is stable across
runs, and it records the advisory ids so a key that no longer resolves is visible rather than
silently unmatched.

**Rollout, per repo, not fleet-wide.** Eight repos can adopt `-fail high` today with no baseline
at all: the five that print zero lines (`ardoise-cli`, `authentik-config`, `croc`,
`perception-js`, `portail`) and three more that have findings but none above medium. They prove
the gate before it ever meets a repo with 227 findings. Everything else adopts a baseline first and shrinks it. Exit 3 is a retry in CI,
never a block, because "I could not tell" is not "you are vulnerable".

**Exit criterion.** A pull request that adds a vulnerable dependency fails. A pull request that
touches one line of a README in a repo with 227 existing findings passes. Removing the baseline
file fails the build rather than passing it, because a missing baseline must not read as an empty
one.

**Depends on.** v1.1, so a repo has a legitimate way to defer what it cannot fix. Ordered after
v5.1: the nightly catches what a per-commit gate structurally cannot, so it is worth more and
costs less.

---

## Housekeeping

Not milestones. Small, known, and each one bites at a bad moment.

- **No release script.** Every tag so far was cut by hand, which the suite versioning convention
  warns against, and the version only exists in the tag because Go 1.24+ stamps it from VCS.
  `scripts/release.sh`, modelled on muse.
- **The install shim documents a fallback that no longer works.** `install.sh` still offers
  `curl | bash install.sh <tool>`, which `facile` bootstrap now refuses by design. Drop the
  fallback from the shim template or teach bootstrap to delegate. Same fix needed across every
  repo carrying the shim, so fix the template.
- **`~/.douane.db` on ruche is orphaned**, written by sweeps from a binary that is no longer
  installed there. Either v5.1 adopts it or it should go, because a stale history file silently
  changes what `[NEW]` means on the next run.

---

## Deliberately not doing

- **Writing a CVE matcher.** Ecosystem version-range semantics are a permanent maintenance tax for
  zero differentiation. douane is a client over existing databases, always.
- **Running trivy *and* grype.** ~90% overlap. Two scanners is a dedup problem, not twice the
  coverage.
- **Gating CI on KEV.** `-fail kev` stays in the binary, it is the right gate in principle and
  costs nothing, but a gate that has never fired across three measurements (732, 1965 and 3816
  findings) is not a safety net and must not be sold as one.
- **A pre-commit hook.** Not "later", not at all. See v5.3: the answer changes with the date, not
  with the diff, so a commit-time trigger fires when nothing changed and is silent when everything
  did. It also needs the network and 30 seconds. `lefthook.yml` in this repo is for developing
  douane and is not a template for consumers.
- **Putting a model in the binary.** Findings must be reproducible and the daemon must hold no API
  key. See v5.2.
- **A letter grade.** findings-per-KLOC has no denominator for CVEs. filet already got burned by
  exactly this.
- **Going public.** Revisit only once the core is cleanly separable from the Facile-specific glue
  (Dokploy, antenne, the suite inventory). If that separation never happens naturally, it was
  never a public tool.
- **Active probing.** douane reads manifests. It never touches a running system.

---

## Open decisions

- **~~Blast radius~~ — settled 2026-08-19.** Client repos are in. GFConseil (122) and LauraHerve
  (92) are the two worst in the fleet; excluding them would hide 29% of the findings.
- **~~Where the sweep runs~~ — settled 2026-08-28, by measurement.** ruche holds 30 repo
  directories, lucy holds 65, so ruche's clone set is not the fleet and nothing keeps it fresh.
  Every number this roadmap quoted before v0.2 was taken on that partial set. The sweep runs where
  the checkouts are complete, and the open work is reaching Dokploy from there rather than
  reaching the code from ruche. Whichever host wins needs `douane` installed and, for v2.1, a Go
  toolchain; ruche has neither today.
- **Whether v4 obsoletes part of v1.** Still open. The v0.2 baseline gives a denominator of 463
  unique advisories but not the overlap; `douane alerts` on one npm-heavy repo answers it cheaply.
- **~~What EPSS threshold means anything here~~ — partly answered 2026-08-28.** The v0.1 cliff was
  an artefact of missing stdlib coverage. The real distribution is 1 finding above 50%, 14 above
  10%, 16 above 5% and 101 above 1%, out of 3816. **5% separates 16 findings from the fleet and is
  worth acting on**; anything below 1% is indistinguishable from zero and should not be ranked as
  if it were signal. What remains open is whether the threshold gates anything, which waits on v3.
- **Whether informational and dev-only findings should count toward the zero-lines target.**
  v2.3 and v2.4 together demote roughly 600 findings without fixing a single one. That is a real
  noise cut and it is also the exact move that lets a tool declare victory by redefining the
  question. The target should probably be restated as zero **prod-scope, non-informational**
  lines, stated once and not moved again. Decide when v2.3 lands, not after the number looks good.
