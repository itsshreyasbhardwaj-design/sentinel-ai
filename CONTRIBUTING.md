# Contributing to Sentinel AI

Thanks for considering a contribution. This document covers what you need to be
productive quickly, and the few conventions that matter enough to be worth
stating.

## Getting set up

Requires **Node 22.5+** (the built-in SQLite driver landed there) and **pnpm**.

```bash
git clone https://github.com/itsshreyasbhardwaj-design/sentinel-ai.git
cd sentinel-ai
pnpm install
pnpm build:packages
pnpm test
```

Nothing else needs to be running. No database, no Redis, no API keys.

```bash
pnpm dev          # dashboard at http://localhost:3000
pnpm scan .       # scan this repository with the CLI
pnpm test         # unit and integration tests
pnpm test:e2e     # Playwright end-to-end suite
pnpm verify       # everything CI runs
```

## Repository layout

```
packages/core       Domain model, severity, scoring, fingerprints, compliance
packages/scanners   Scanner registry, rule engine, native + external adapters
packages/ai         Explanation, prioritization, remediation
packages/reports    SARIF, PDF, HTML, Markdown, CSV, JSON export
packages/platform   Storage, cache, jobs, auth, rate limiting, encryption
packages/cli        Command-line interface
apps/web            Next.js dashboard and REST API
fixtures/           Intentionally vulnerable code the test suite scans
```

Dependencies flow in one direction: `core` ← everything else. If you find
yourself wanting `core` to import from `scanners`, the abstraction is in the
wrong place.

## Adding a detection rule

Most contributions are new rules. A rule is a single object:

```ts
{
  id: 'js-my-rule',
  title: 'Short, specific statement of what is wrong',
  description: 'What the flaw is, in one or two sentences.',
  severity: 'high',
  kind: 'sast',
  confidence: 'medium',
  languages: ['javascript', 'typescript'],
  patterns: [/dangerous\s*\(/],
  excludePatterns: [/safe_wrapper/],
  validate: all(notInComment, notInTests),
  taxonomy: {
    cwe: ['CWE-123'],
    owaspTop10: ['A03:2021-Injection'],
    references: [{ title: 'CWE-123', url: 'https://cwe.mitre.org/…' }],
  },
  remediationHint: 'The smallest correct change.',
}
```

Every new rule needs:

1. **A fixture.** Add the vulnerable pattern to `fixtures/vulnerable-app/`.
2. **A test.** Assert in `packages/scanners/src/engine.test.ts` that it fires.
3. **Taxonomy.** At minimum a CWE. Without it the finding cannot participate in
   compliance mapping.
4. **A knowledge-base topic**, if no existing topic covers it — see
   `packages/ai/src/knowledge/topics.ts`. A rule with no topic falls back to
   generic advice, which is a much worse experience.

### Rules are tuned for precision

This is the one guideline worth arguing about, so here is the reasoning: a
scanner that produces false positives gets muted, and a muted scanner finds
nothing. A rule that misses some real cases is strictly better than one that
floods the report.

Concretely, prefer a `validate` callback over a broader pattern. The helpers in
`packages/scanners/src/rules/engine.ts` — `notInComment`, `notInTests`,
`contextMatches`, `hasDynamicInterpolation` — exist for this.

If you cannot get a rule below roughly one false positive in ten, ship it at
`confidence: 'low'` so it is ranked accordingly rather than not shipping it.

## Adding a scanner

Implement the `Scanner` interface and call `register`. That is the whole
extension point — selection, availability reporting, scoring, compliance mapping
and every export format come for free. See [`docs/extending.md`](docs/extending.md).

If you are wrapping an external binary:

- Probe with `probeBinary` so a missing tool is reported, not thrown.
- Use `run` from `packages/scanners/src/exec.ts`. Never `exec` with a shell —
  repository names and refs are attacker-controlled.
- Set `supersedes` if the tool fully covers a bundled scanner's domain.

## Code conventions

- **Strict TypeScript.** No `any` without a comment justifying it.
- **Comments explain *why*.** The code already says what it does. Comment the
  non-obvious constraint, the trade-off, or the bug the line prevents.
- **Errors carry a code.** Use the `errors` helpers from `@sentinel/core`, so
  every failure maps to an HTTP status without route handlers guessing.
- **Never log a secret.** The logger redacts, but do not rely on it — pass an
  identifier rather than a value.
- **Findings are relative.** No absolute host paths in a finding, ever. There is
  a test enforcing this.

## Tests

- Unit tests live beside the code as `*.test.ts`.
- Integration tests scan `fixtures/` and assert on real output.
- `packages/scanners/src/security.test.ts` guards the controls protecting the
  *host running Sentinel* — zip slip, zip bombs, command injection, symlink
  escapes. A regression there is a vulnerability in this product, so those tests
  should be treated as non-negotiable.

Write the test so it fails for the right reason. `expect(findings.length > 0)`
passing because an unrelated rule fired is worse than no test.

## Pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/):
  `feat(scanners): detect unsafe MCP server configuration`
- Run `pnpm verify` before pushing.
- Describe the *why*, not just the what. If you made a trade-off, say so.
- Security-relevant changes should say what threat model they address.

## Reporting security issues

Please do not open a public issue. See [SECURITY.md](SECURITY.md).

## Code of conduct

Be decent to each other. Assume good faith, critique code rather than people, and
remember that the person on the other end is usually doing this in their spare
time.
