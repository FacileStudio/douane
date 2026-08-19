# douane roadmap

The wiki holds the evidence (`~/.jardin/memory/projects/douane.md`). This file holds the order.

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

We are 732 lines away from it. That gap is the roadmap.

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

## Order of work

Evidence, not milestone numbers, sets this. Current order:

1. ~~**v1.2** feed caching~~ — shipped 2026-08-19
2. ~~**v1.3** `douane sweep`~~ — shipped 2026-08-19
3. **v1.4** report by fix — the cheapest 3.4× noise cut on the board
4. **v2.1** govulncheck reachability — kills most of the 109 Go findings
5. **v3** deployed-or-not — promoted; now the sharpest axis available
6. **v1.1** permits — demoted; needed once the volume is survivable
7. **v4** Dependabot, **v5** automation

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

**Exit criterion — met.** Second run within the TTL makes zero requests to KEV or EPSS
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

**Exit criterion — met.** `douane sweep ~/Code/Facile` completes in **13s** warm (the shell
loop it replaces took ~2min) and reproduces the v0.1 total of 732 findings across 27 repos.
A second run reports zero `[NEW]`.

**Depends on.** v1.2 — without caching this is 27 KEV downloads.

### v1.4 Report by fix, not by finding

**Why.** 732 findings are 217 bumps and 230 advisories. The same `x/crypto` line appears in 16
repos and the same `hono` advisory 67 times. Printing per finding is printing the same decision
dozens of times, and it is the single largest source of noise measured so far.

**What.** Default output groups findings by the action that clears them: one line per
(package, target version), with the count and worst rank of what it clears. `-by finding`
restores the flat list. JSON keeps both shapes — the grouping is derived, never lossy.

**Exit criterion.** The suite sweep prints ≤ 250 primary lines instead of 732, and every finding
is still reachable in the JSON output.

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

---

## v2 — cut the noise

### v2.1 govulncheck adapter (reachability)

**Why.** The one genuinely irreplaceable tool in the space. Call-graph analysis reports a Go CVE
only if your code can reach the vulnerable function. The baseline says 109 Go findings, nearly
all transitive `x/crypto` and `x/oauth2` — the exact shape reachability deletes.
`Finding.Exploit.Reachable` is already a `*bool` waiting for it: `nil` means unchecked, and must
never be conflated with `false`.

**What.** A `Scanner` interface with `govulncheck` as its second implementation, invoked when a
`go.mod` is present and the binary is on PATH. Absent binary degrades to `nil`, never to `false`.

**Exit criterion.** The Go finding count drops measurably against the 109 baseline, and every
surviving Go finding reports `reachable: true`.

**Depends on.** Nothing. Needs `govulncheck` installed on ruche, which currently has no Go.

### v2.2 Severity for Go advisories

**Why.** `GO-*` records omit `database_specific.severity`, so 43 findings read `UNKNOWN` — all of
them Go. With KEV silent and EPSS thin, severity is doing more ranking work than the original
design assumed, and it is blank exactly where the fleet's own code lives.

**What.** Compute the CVSS v3 base score from the vector already present in `severity[]` and map
it to a band. This is the published formula, not a heuristic.

**Exit criterion.** A tronc scan reports a real severity for every finding carrying a CVSS
vector, and a unit test pins three known vectors to their published scores.

**Depends on.** Nothing.

---

## v3 — is it actually deployed?  *(promoted)*

**Why.** A CVE in a repo last deployed in March is a chore. The same CVE in the container serving
production is an incident. With KEV at zero and EPSS flat, this is the sharpest remaining axis —
and nothing else in the stack can make the distinction.

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

**What.** A jardin flow on ruche running `douane sweep` nightly, diffing against sqlite, alerting
through **antenne** only on what is new or newly escalated. Given the baseline, the alert
threshold is "new since yesterday", never the standing total.

**Exit criterion.** A quiet night produces no alert at all. A newly published advisory affecting
a deployed service produces exactly one.

**Depends on.** v1.2, v1.3, and enough of v1.4/v2.1/v3 that a nightly alert is readable.

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
reports is better computed once, in the binary), and a stable JSON shape.

---

## Deliberately not doing

- **Writing a CVE matcher.** Ecosystem version-range semantics are a permanent maintenance tax for
  zero differentiation. douane is a client over existing databases, always.
- **Running trivy *and* grype.** ~90% overlap. Two scanners is a dedup problem, not twice the
  coverage.
- **Gating CI on KEV.** `-fail kev` stays in the binary — it is the right gate in principle and
  costs nothing — but a gate that has never fired on 732 findings is not a safety net, and must
  not be sold as one.
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
- **Where the sweep runs.** ruche has the Dokploy API and the cron; lucy has the checkouts. The
  baseline ran on ruche, so the checkouts are there too — but they are clones for scanning, not
  the working copies, and nothing keeps them fresh. v5.1 needs an answer: a `git fetch` step in
  the flow, or the sweep moves to lucy and reaches Dokploy over the network.
- **Whether v4 obsoletes part of v1.** Still open. The baseline gave a denominator (230 unique
  advisories) but not the overlap; `douane alerts` on one npm-heavy repo answers it cheaply.
- **What EPSS threshold means anything here.** With two findings above 5% and a cliff below,
  a fixed cutoff is arbitrary. Revisit once v3 says which of them are deployed.
