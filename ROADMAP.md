# douane roadmap

Design decisions and their evidence live in the wiki (`~/.jardin/memory/projects/douane.md`).
This file carries the order.

## Shipped — v0

Lockfile → OSV.dev batch API → KEV + EPSS enrichment → sqlite history → ranked output.

- `internal/inventory` — go.mod, package-lock.json, bun.lock, Cargo.lock
- `internal/osv` — batch query, detail fetch, alias resolution, branch-correct fix version
- `internal/enrich` — CISA KEV, FIRST EPSS, both degrading to a warning when unreachable
- `internal/store` — sweeps and findings in sqlite; marks what is new since the last sweep
- `internal/output` — auto/text/line/json

**Exit criteria met:** builds, `filet check` clean at default thresholds, `go test ./...`
green, runs offline-degraded, exit codes match filet's contract.

## Next — v1: reachability

`govulncheck` adapter behind a `Scanner` interface. Go-only, but it is the one genuinely
irreplaceable tool in the space: call-graph analysis removes most findings as unreachable.
`Finding.Exploit.Reachable` already exists as a `*bool` for exactly this.

**Exit criterion:** a Go repo's finding count drops measurably, and every surviving finding
says `reachable: true`.

## v2: the Dependabot collector

`gh api /repos/FacileStudio/<repo>/dependabot/alerts` across the suite. Pure read, no
scanning. Probably surfaces alerts that already exist and nobody has ever looked at.

**Exit criterion:** one command lists every open alert across all suite repos.

## v3: containers and deployment status

`trivy image` (not grype — pick one) against what Dokploy reports as running on ruche. A CVE
in an undeployed repo is a chore; the same CVE in a live container is an incident.

**Exit criterion:** findings carry a `deployed` flag sourced from the Dokploy API.

## v4: the sweep daemon

`douane sweep` over the whole suite on a schedule, alerting through **antenne**, diffing
against the sqlite history so a quiet night stays quiet.

**Exit criterion:** a nightly run over a healthy suite emits nothing at all.

## Deliberately not doing

- **Writing a CVE matcher.** Ecosystem version-range semantics are a permanent tax for zero
  differentiation. douane is a client over existing databases, always.
- **Running trivy *and* grype.** They overlap ~90%. Two scanners is a dedup problem, not
  twice the coverage.
- **Putting a model in the binary.** douane stays deterministic and emits JSON; a `/douane`
  skill does the judging, exactly as `filet` does. Keeps the daemon key-free and findings
  reproducible.
- **A letter grade.** findings-per-KLOC has no denominator for CVEs. filet already got burned.
- **Going public.** Revisit only once the core is cleanly separable from the Facile-specific
  glue (Dokploy, antenne, the suite inventory).

## Open decisions

- **Suppressions.** Design is settled — every entry requires an `expires:` date and a reason,
  and douane fails loudly when one lapses — but nothing is implemented. A suppression that
  never expires is a lie about your attack surface.
- **Feed caching.** KEV and EPSS are refetched every run. Needs a TTL in the `feed_cache`
  table before a 26-repo sweep is reasonable.
- **Blast radius.** Facile only, or client repos (GFConseil, LauraHerve) too? Decides whether
  the inventory is a config file or a real store.
