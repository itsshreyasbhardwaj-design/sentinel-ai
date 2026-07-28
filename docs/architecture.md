# Architecture

This document explains how Sentinel is put together and, more usefully, *why*.
Most of the structure follows from two constraints:

1. **It must work with nothing configured.** No database, no API key, no network.
   A security tool people have to sign up for is a security tool most people
   never run.
2. **It must never overstate what it checked.** A report that implies coverage it
   did not have is worse than no report, because someone will act on it.

---

## Package graph

```
                         ┌─────────────────┐
                         │  @sentinel/core │
                         │                 │
                         │  Domain model   │
                         │  No I/O         │
                         │  No deps but    │
                         │  zod            │
                         └────────┬────────┘
                                  │
        ┌───────────────┬─────────┼─────────┬───────────────┐
        │               │         │         │               │
┌───────┴──────┐ ┌──────┴─────┐ ┌─┴───────┐ ┌───────────────┴─┐
│  scanners    │ │  ai        │ │ reports │ │  platform       │
│              │ │            │ │         │ │                 │
│  Registry    │ │ Knowledge  │ │ SARIF   │ │  Storage        │
│  Rule engine │ │ OpenRouter │ │ PDF     │ │  Cache          │
│  Workspace   │ │            │ │ HTML    │ │  Jobs           │
│  Advisories  │ │            │ │ MD/CSV  │ │  Auth           │
└───────┬──────┘ └──────┬─────┘ └────┬────┘ └────────┬────────┘
        │               │            │               │
        └───────────────┴─────┬──────┴───────────────┘
                              │
              ┌───────────────┴───────────────┐
              │                               │
      ┌───────┴────────┐            ┌─────────┴────────┐
      │ @sentinel/cli  │            │  apps/web        │
      │                │            │  Next.js         │
      └────────────────┘            └──────────────────┘
```

Dependencies flow one way. `core` imports nothing from the platform and performs
no I/O, which is what lets it be tested exhaustively and imported from a browser
bundle (via the `@sentinel/core/constants` subpath).

---

## The scan pipeline

```
   Target (local | github | archive)
        │
        ▼
   ┌─────────────────┐   git clone --depth 1, or hardened ZIP extraction,
   │  materialize    │   or a validated local path
   └────────┬────────┘
            ▼
   ┌─────────────────┐   Ignore rules, size and count limits, no symlink
   │  walk files     │   following, language detection, content digests
   └────────┬────────┘
            ▼
   ┌─────────────────┐   Probe availability; external tools supersede the
   │  select         │   bundled equivalents they fully cover
   │  scanners       │   Skipped scanners are recorded with a reason
   └────────┬────────┘
            ▼
   ┌─────────────────┐   Sequential across scanners, concurrent within each.
   │  run scanners   │   A failure is recorded and survived, never fatal.
   └────────┬────────┘
            ▼
   ┌─────────────────┐   Stable fingerprints, suppression, risk scores
   │  normalize      │
   └────────┬────────┘
            ▼
   ┌─────────────────┐   Same issue from two scanners collapses to one;
   │  dedupe         │   corroboration raises confidence
   └────────┬────────┘
            ▼
   ┌─────────────────┐   Per-category and overall, excluding domains that
   │  score          │   were never analyzed
   └────────┬────────┘
            ▼
   ┌─────────────────┐   Explanations, priorities, executive summary
   │  enrich (AI)    │   Failure here loses analysis, never findings
   └────────┬────────┘
            ▼
   ┌─────────────────┐
   │  persist        │
   └─────────────────┘
```

### Why scanners run sequentially

Each scanner is internally concurrent (`mapLimit` over files). Running eight of
them at once would thrash the disk, make progress reporting meaningless, and turn
a memory spike in one into an out-of-memory kill for all. The wall-clock cost is
small because the bottleneck is IO within a scanner, not across them.

### Why a scanner failure is not fatal

A partial result with an explicit "trivy failed: database unavailable" row is far
more useful than an exception that discards the work of the other eight scanners.
Every run is recorded in `scannerRuns` with `ok`, `skipped` or `failed` and a
reason, and that table appears in every report.

---

## Fingerprints and why they exclude line numbers

A finding's identity is
`sha256(ruleId + path + normalizedSnippet + component + discriminator)`.

Line numbers are deliberately absent. If they were included, adding an import at
the top of a file would resolve every finding below it and immediately
reintroduce them one line lower. Trend tracking, "introduced by this PR", and
suppression persistence all depend on identity surviving that.

The snippet is whitespace- and case-normalized before hashing, so reformatting
does not invent new findings either.

---

## Scoring

Per category:

```
score = 100 − Σ (penalty(severity) with diminishing returns)
```

Two properties matter:

**Diminishing returns.** The 40th medium finding contributes far less than the
first. Without this, every large legacy repository scores zero and the number
stops distinguishing anything.

**Unanalyzed ≠ clean.** A category with no scanner run is excluded from the
overall average rather than contributing a free 100. A SAST-only scan is graded
against SAST, and the UI shows the other categories as "not analyzed".

Overall is a weighted mean over analyzed categories only. Secrets carry the
highest weight because a leaked live credential is an incident already in
progress, not a backlog item.

---

## The AI layer

The default analyst is a **curated knowledge base**, not a model. It maps each
finding to a topic and composes an explanation, business impact, mechanism and
concrete fixes with language-appropriate code examples.

This is the default for four reasons:

1. It works offline and costs nothing, so the product functions in the situation
   most open-source tools actually run in.
2. It is deterministic, which means it can be snapshot-tested.
3. The fixes are reviewed and safe to paste — something not assertable about
   generated code.
4. It is fast: 50 explanations in single-digit milliseconds.

When `OPENROUTER_API_KEY` is set, a model rewrites the *prose* to be specific to
the code in front of it. Three things deliberately do not change:

- **Fixes stay from the knowledge base.** They are reviewed; generated code is not.
- **Prioritization stays arithmetic.** Ranking a work queue must be reproducible,
  and "why is this first" deserves an auditable answer.
- **Caveats stay computed.** They are derived from what actually ran. A model
  must not be able to soften an honest statement about coverage.

Every model call falls back to the knowledge base on error, timeout or malformed
response, so enabling a model can improve output but can never take the product
down.

---

## Adapter pattern

Storage, cache, jobs and auth all follow the same shape: an interface, a
zero-configuration default, and an optional upgrade selected by environment.

| Concern | Default | Upgrade | Selected by |
| --- | --- | --- | --- |
| Storage | SQLite (`node:sqlite`) | Postgres / Supabase | `DATABASE_URL` |
| Cache | In-memory LRU | Redis | `REDIS_URL` |
| Jobs | In-process queue | Trigger.dev | `TRIGGER_SECRET_KEY` |
| Auth | Local dev identity | Clerk | `CLERK_SECRET_KEY` |
| AI | Knowledge base | OpenRouter | `OPENROUTER_API_KEY` |

`GET /api/health` reports which is active, so a deployment that thought it was
using Postgres and silently fell back is visible rather than surprising.

The optional drivers are loaded through `optionalImport`, which uses a variable
specifier so bundlers leave them alone, and `process.getBuiltinModule` for Node
built-ins that predate bundler module lists.

---

## Security architecture

Sentinel's own attack surface is the interesting one: it processes repositories
and archives chosen by someone else.

| Threat | Control |
| --- | --- |
| Zip slip | Two independent checks per entry: name shape and resolved path |
| Zip bomb | Per-entry size, total size, entry count and compression-ratio limits |
| Command injection | `execFile` with an argument array; no shell, ever |
| Credential theft by a scanner | Child processes get only `PATH`, `HOME`, `LANG` |
| Symlink escape | The walker never follows symlinks |
| Resource exhaustion | File count, size, line length and time all bounded |
| Secret leakage | Masked in the scanner, before the value becomes a finding |
| Host path disclosure | Findings carry relative paths only, enforced by test |
| Spreadsheet formula injection | CSV values starting `= + - @` are prefixed |
| Unauthenticated production | Startup fails rather than serving open |

These are covered by `packages/scanners/src/security.test.ts`. A regression there
is a vulnerability in this product, not a failing test.

---

## Request pipeline

Every API route goes through one `handle` wrapper that applies authentication,
rate limiting, error shaping and security headers. A route cannot forget one of
those, because the handler signature does not typecheck without it.

Unexpected errors log their detail and return a generic message. A stack trace in
an API response is precisely the information-disclosure finding this product
reports on.

---

## Notable trade-offs

**The rule engine is line-oriented, not AST-based.** It works uniformly across
eight languages with no per-language parser, degrades gracefully on files it does
not fully understand, and cannot be defeated by a syntax error. The cost is
precision, which is bought back with `validate` callbacks that have whole-file
context. Rules that need real semantic analysis should defer to Semgrep, which is
why the integration exists.

**The PDF writer is hand-rolled.** Every JS PDF library either bundles a headless
browser or a font-embedding stack. For a text report neither is warranted, and
for a *security* tool a smaller dependency tree is a feature.

**The ZIP reader is hand-rolled.** Archive extraction is the most
attacker-reachable code in the product. A small, auditable implementation that
enforces zip-slip and zip-bomb limits directly beats hoping a dependency does.

**There is no root `loading.tsx`.** It would make Next stream a 200 before the
existence check runs, so missing scans would return `200 OK` with "Not found" in
the body. See [`apps/web/src/app/README.md`](../apps/web/src/app/README.md).
