# douane roadmap

The wiki holds the evidence (`~/.mycelium/memory/projects/douane.md`). This file holds the order.

Every milestone has an **exit criterion** — something verifiable, not a feeling. Milestones that
name no dependency can be built in parallel.

---

## The through-line

douane exists to answer one question: **what should I fix today?**

Every milestone is judged against that. A feature that adds findings without adding decisions is
a regression, however impressive the coverage number. The calibration target, inherited from
filet, is unforgiving:

> A sweep over a healthy suite prints **zero lines**.

We are nowhere near it. That gap is the roadmap.

---

## v0 — shipped 2026-08-19

Lockfile → OSV.dev batch API → KEV + EPSS → sqlite history → ranked output.

Four ecosystems (`go.mod`, `package-lock.json`, `bun.lock`, `Cargo.lock`), one dependency beyond
stdlib, no scanner binaries, no vulnerability database to download.

`filet check` clean at default thresholds · `go test ./...` green · degrades to a warning when
either feed is unreachable · exit codes match filet's contract.

---

## v0.1 — measure the baseline

**Why.** We have one data point: 83 findings on Glure. Nobody knows what the suite total is, and
every triage decision downstream depends on that number. If it is 200, suppressions are a nicety.
If it is 2000, they are the product.

**What.** Run douane across all 26 repos under `~/Code/Facile`, record the total, the split by
ecosystem, the count on KEV, and the count with no fix available. Write it to the wiki, not to
the repo — it is a map of the attack surface.

**Exit criterion.** A recorded number for: total findings, findings on KEV, findings with no fix,
and the single worst repo.

**Depends on.** Nothing. Do this first; it may reorder everything below.

---

## v1 — make it usable daily

The blocker for daily use is not coverage, it is that **you cannot tell douane you have already
looked at something**. Right now day two prints exactly what day one printed, and that is how a
tool gets ignored.

### v1.1 Suppressions with mandatory expiry

**Why.** Without suppression, the output never shrinks and stops being read. With unbounded
suppression, findings vanish permanently and the tool lies. The name already settled this: a
suppression is a **temporary permit**, and permits expire.

**What.** `douane.yml` in the repo. Each entry requires an `expires:` date and a `reason:` — both
mandatory, rejected at parse time if missing. douane **fails loudly** when a permit lapses rather
than silently reinstating the finding, and lists permits expiring within 14 days on every run.

**Exit criterion.** A suppressed finding disappears from output; the same finding reappears with
an `EXPIRED PERMIT` marker once its date passes; a `douane.yml` entry missing `expires:` exits 2
with a message naming the line.

**Depends on.** Nothing.

### v1.2 Feed caching

**Why.** Every run refetches the whole KEV catalogue (1670 entries) and re-queries EPSS. Fine for
one repo, absurd across 26, and it makes douane useless on a plane.

**What.** Cache both feeds in the existing `feed_cache` table with a TTL (KEV daily, EPSS daily).
`-refresh` forces a fetch; a stale cache is used with a warning when the network fails.

**Exit criterion.** Second run within the TTL makes zero requests to KEV or EPSS. With the network
down and a warm cache, ranking is still fully populated.

**Depends on.** Nothing.

### v1.3 `douane sweep`

**Why.** douane is currently a per-repo tool. The reason it exists is the fleet.

**What.** `douane sweep [dir]` walks a directory of repos, scans each, and reports across all of
them — grouped by repo, ranked globally, with the same history diff. One row per repo in the
summary.

**Exit criterion.** `douane sweep ~/Code/Facile` completes in under 60s warm, and a second run
reports zero new findings.

**Depends on.** v1.2 — without caching this is 26 KEV downloads.

---

## v2 — cut the noise

Two independent tracks. Build either first.

### v2.1 govulncheck adapter (reachability)

**Why.** The one genuinely irreplaceable tool in the space. Call-graph analysis reports a Go CVE
only if your code can reach the vulnerable function, which typically removes most findings.
`Finding.Exploit.Reachable` is already a `*bool` waiting for it — `nil` means unchecked, and must
never be conflated with `false`.

**What.** A `Scanner` interface with `govulncheck` as its second implementation, invoked when a
`go.mod` is present and the binary is on PATH. Absent binary degrades to `nil`, never to `false`.

**Exit criterion.** On a suite Go repo, finding count drops measurably against v0, and every
surviving Go finding reports `reachable: true`.

**Depends on.** Nothing.

### v2.2 Severity for Go advisories

**Why.** `GO-*` records omit `database_specific.severity`, so most Go findings read `UNKNOWN` and
under-rank whenever KEV and EPSS are both silent.

**What.** Compute the CVSS v3 base score from the vector already present in `severity[]` and map
it to a band. This is the published formula, not a heuristic.

**Exit criterion.** A tronc scan reports a real severity for every finding carrying a CVSS vector,
and a unit test pins three known vectors to their published scores.

**Depends on.** Nothing.

---

## v3 — is it actually deployed?

**Why.** A CVE in a repo last deployed in March is a chore. The same CVE in the container serving
production is an incident. Nothing else in the stack can make that distinction, and it is the
sharpest prioritiser available after KEV.

**What.** `trivy image` (not grype — they overlap ~90%, pick one) against the images Dokploy
reports as running on ruche, correlated back to findings. Trivy runs via `docker run` with a
cached DB volume, so nothing new lands on PATH.

**Exit criterion.** Findings carry a `deployed` flag sourced from the Dokploy API, and
`douane sweep --deployed-only` returns a strictly smaller set.

**Depends on.** v1.3.

---

## v4 — the Dependabot collector

**Why.** GitHub is very likely already raising alerts on these repos and nobody has ever opened
the tab. Pure read, no scanning, cheap — and it may reveal that part of this is solved.

**What.** `douane alerts` over `gh api /repos/FacileStudio/<repo>/dependabot/alerts`, merged into
the same `Finding` shape and deduped on the alias graph alongside OSV results. `Sources` gains a
second entry, which is free intelligence about each source's false-positive rate.

**Exit criterion.** One command lists every open Dependabot alert across the suite, and findings
seen by both sources report `sources: ["osv", "dependabot"]`.

**Depends on.** Nothing.

---

## v5 — automation

### v5.1 The nightly daemon

**Why.** douane's verdict changes when the world changes, not when you commit. A scanner you must
remember to run reports on your last panic, not your current risk.

**What.** A mycelium flow on ruche running `douane sweep` nightly, diffing against sqlite, alerting
through **antenne** only on what is new or newly escalated to KEV.

**Exit criterion.** A quiet night produces no alert at all. A CVE newly added to KEV produces
exactly one.

**Depends on.** v1.1, v1.2, v1.3.

### v5.2 The `/douane` skill

**Why.** The binary must never call a model — it stays deterministic, offline-capable and
key-free. The judgment lives in a skill, exactly as `filet` splits it.

**What.** Runs `douane scan -format json`, triages, and reports **by fix rather than by finding**
("23 findings, 19 clear with one bump of `foo`") before touching anything. Fixes causes, then runs
the project's tests. Two hard rules: never bump a lockfile without running the tests, and never
add a suppression to make the output green. Escalates to `/facile-plan` when the fix is
architectural — which is what an empty `fixed_in` usually means.

**Exit criterion.** The skill fixes a real finding in a suite repo, the tests pass, and it reports
honestly what it left behind and why.

**Depends on.** v1.1 (it needs somewhere legitimate to defer a finding), and a stable JSON shape.

---

## Deliberately not doing

- **Writing a CVE matcher.** Ecosystem version-range semantics are a permanent maintenance tax for
  zero differentiation. douane is a client over existing databases, always.
- **Running trivy *and* grype.** ~90% overlap. Two scanners is a dedup problem, not twice the
  coverage.
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

- **Blast radius.** Facile only, or client repos (GFConseil, LauraHerve) too? Decides whether the
  inventory is a config file or a real store. Blocks v1.3's design.
- **Where the sweep runs.** ruche has the Dokploy API and the cron; lucy has the code checkouts.
  If they diverge, v3 and v1.3 want different homes.
- **Whether v4 obsoletes part of v1.** If Dependabot is already covering the npm side well, the
  effort belongs in reachability and deployment correlation instead. v0.1's baseline should answer
  this.
