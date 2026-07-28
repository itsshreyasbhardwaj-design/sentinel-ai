# Extending Sentinel

Sentinel has two extension points, one small and one smaller: **rules** and
**scanners**. Both are plain objects. Neither requires touching anything else.

---

## Adding a detection rule

Most contributions are rules. Add one to the appropriate pack in
`packages/scanners/src/rules/`.

```ts
{
  id: 'py-my-rule',
  title: 'Session token generated from a predictable source',
  description:
    'The value is derived from a non-cryptographic generator, so an attacker '
    + 'who observes a few tokens can compute the rest.',
  severity: 'high',
  kind: 'sast',
  confidence: 'medium',
  languages: ['python'],

  patterns: [/\brandom\.(?:choice|randint|random)\s*\(/],
  excludePatterns: [/secrets\./],

  validate: all(notInComment, notInTests, contextMatches(/token|session|otp/i)),

  taxonomy: {
    cwe: ['CWE-338'],
    owaspTop10: ['A02:2021-Cryptographic Failures'],
    references: [{ title: 'CWE-338', url: 'https://cwe.mitre.org/data/definitions/338.html' }],
  },

  remediationHint: 'Use `secrets.token_urlsafe(32)`.',
}
```

### Validators

Patterns alone are usually too blunt. The helpers in `rules/engine.ts` sharpen
them with context:

| Helper | Purpose |
| --- | --- |
| `notInComment` | Skip lines that are pure comments |
| `notInTests` | Skip test, fixture and example paths |
| `contextMatches(re, radius)` | Require a pattern within N lines — the signal is often on the enclosing function, not the matched line |
| `hasDynamicInterpolation(text)` | Distinguish `query("SELECT 1")` from `query("SELECT " + id)` |
| `all(...)` | Compose several validators |

A rule can also supply its own function with access to the whole file:

```ts
validate: (match) => match.lines.some((line) => /import boto3/.test(line)),
```

### The precision guideline

Rules are tuned for **precision over recall**. A scanner that produces false
positives gets muted, and a muted scanner finds nothing. A rule that misses some
real cases is strictly better than one that floods the report.

Practically: reach for a `validate` callback before broadening a pattern. If you
cannot get below roughly one false positive in ten, ship at `confidence: 'low'`
so it is ranked accordingly rather than not shipping it.

### Checklist

1. Add the vulnerable pattern to `fixtures/vulnerable-app/`.
2. Assert it fires, in `packages/scanners/src/engine.test.ts`.
3. Attach at minimum a CWE — without taxonomy the finding cannot participate in
   compliance mapping.
4. Add a knowledge-base topic if none covers it (below). A rule without one falls
   back to generic advice.

---

## Adding a knowledge-base topic

`packages/ai/src/knowledge/topics.ts` is what turns a rule id into an
explanation someone can act on. Each topic answers four questions.

```ts
{
  id: 'my-topic',
  matches: ['my-rule', 'CWE-338'],   // rule-id fragments and CWE ids

  plainEnglish:
    'What is wrong, for the engineer who has to fix it. No jargon, no alarmism.',

  businessImpact:
    'What it costs if exploited, in terms a non-engineer can act on.',

  technicalImpact:
    'What an attacker actually gains.',

  howItHappens:
    'The mechanism. Usually: the safe path was less convenient than the unsafe one.',

  confidence: 0.85,

  fixes: (finding) => [
    fix('Do the correct thing', 'Why this is the complete fix, not a mitigation.', {
      language: 'python',
      code: '# Before\n…\n\n# After\n…',
      effort: 'small',
      autoApplicable: false,
    }),
  ],
}
```

Topic selection prefers rule-id matches over CWE matches, so a specific rule gets
specific advice rather than the generic text its CWE would select.

Write the fixes as if reviewing a colleague's PR: show before and after, explain
why the change is correct, and be honest when a fix is a mitigation rather than a
solution.

---

## Adding a scanner

A scanner is one object implementing `Scanner`. Register it and it participates
in selection, availability reporting, scoring, compliance mapping, every export
format and the dashboard — nothing else changes.

```ts
import { register, type Scanner } from '@sentinel/scanners';
import { mapLimit } from '@sentinel/core';

export const myScanner: Scanner = {
  id: 'my-scanner',
  name: 'My Scanner',
  kind: 'sast',
  origin: 'native',
  description: 'One sentence describing what it covers. Shown in the UI.',
  languages: ['typescript'],

  async isAvailable() {
    return { available: true };
  },

  async scan(ctx) {
    const results = await mapLimit(ctx.files, ctx.options.concurrency, async (file) => {
      if (ctx.signal?.aborted) return [];
      const content = await ctx.readFile(file);
      // …
      return findings;
    });
    return results.flat();
  },
};

register(myScanner);
```

### Wrapping an external tool

```ts
export const myToolScanner: Scanner = {
  id: 'mytool',
  name: 'MyTool',
  kind: 'iac',
  origin: 'external',
  description: 'MyTool policy scanning.',

  // Naming a bundled scanner here makes it stand down when this tool is present.
  supersedes: ['native-iac'],

  async isAvailable() {
    const probe = await probeBinary('mytool', ['--version']);
    return probe.available
      ? { available: true, version: probe.version }
      : { available: false, reason: 'mytool is not installed (brew install mytool)' };
  },

  async scan(ctx) {
    const result = await run('mytool', ['--json', ctx.root], {
      cwd: ctx.root,
      okExitCodes: [0, 1],       // most scanners exit 1 when they find something
      signal: ctx.signal,
    });
    return (tryParseJson<MyToolOutput>(result.stdout)?.findings ?? []).map(toFinding);
  },
};
```

Rules for external adapters:

- **Probe, do not throw.** A missing binary is reported as unavailable with an
  actionable reason, so the coverage table tells the user how to fix it.
- **Never use a shell.** `run` uses `execFile` with an argument array.
  Repository names, refs and paths are attacker-controlled.
- **Normalize severity** with `normalizeSeverity` — every tool has its own
  vocabulary, and an unrecognized value must be mis-ranked rather than dropped.
- **Set `supersedes`** only if the tool genuinely covers the whole domain. Where
  two scanners are complementary — Gitleaks and the bundled secret scanner, for
  example — leave both running: agreement raises confidence.

### The scan context

| Field | Description |
| --- | --- |
| `ctx.root` | Absolute path to the materialized repository |
| `ctx.files` | Filtered file list with language and digest |
| `ctx.readFile(entry)` | Cached read — the same file is read once across all scanners |
| `ctx.options` | Limits: `maxFiles`, `maxFileSizeBytes`, `concurrency`, `allowNetwork` |
| `ctx.signal` | Abort signal. Check it in long loops. |
| `ctx.logger` | Redacting logger |
| `ctx.onProgress(msg)` | Report progress from a long-running scanner |

Respect `ctx.options.allowNetwork`. A scanner that phones home when the operator
disabled network access is a bug, not a feature.

---

## Adding a compliance framework

`packages/core/src/compliance.ts`. Controls map to taxonomy tags rather than rule
ids, so a framework keeps working when scanners are swapped.

```ts
export const MY_FRAMEWORK: ComplianceFramework = {
  id: 'my-framework-1.0',
  name: 'My Framework',
  version: '1.0',
  description: 'What it covers.',
  controls: [
    {
      id: 'MF-1',
      title: 'Injection defences',
      description: 'Untrusted input is never interpreted as code.',
      mappedTaxonomy: ['CWE-89', 'CWE-78', 'A03:2021'],
    },
  ],
};
```

Tag forms: `CWE-79`, `A03:2021`, `LLM01:2025`, `kind:secrets`, `has:cve`.

Use a `kind:` tag when a control depends on a whole analysis domain. That is what
lets the engine report `needs-review` instead of `pass` when the domain was never
scanned — the single most important property of the compliance output.

---

## Adding an export format

`packages/reports/src/`. Write the renderer, then register it in
`exportReport` with a content type and file extension.

Two things every format must preserve:

- **Suppressed findings are omitted**, not marked. A downstream tool that renders
  them as open defeats the suppression.
- **Coverage caveats are included.** A report that omits what was not checked is
  the failure mode this product exists to avoid.
