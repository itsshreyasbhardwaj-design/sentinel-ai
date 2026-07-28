<div align="center">

# Sentinel AI

**AI-native application security. Findings you can act on, not a wall of alerts.**

[![CI](https://github.com/itsshreyasbhardwaj-design/sentinel-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/itsshreyasbhardwaj-design/sentinel-ai/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A522.5-green.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/typescript-strict-blue.svg)](https://www.typescriptlang.org)

</div>

---

Sentinel scans a repository across nine security domains, explains every finding
in plain English, ranks them by what to fix first, and tells you exactly how.

It runs with **no API key, no database and no network access**. That is a design
constraint, not a limitation: a security tool that only works once you have
signed up for something is a security tool most people never run.

```bash
npx sentinel .
```

<div align="center">

_Screenshot placeholder — `docs/images/dashboard.png`_
_Screenshot placeholder — `docs/images/finding-detail.png`_
_Screenshot placeholder — `docs/images/trend.png`_

</div>

---

## What makes it different

**It reviews AI applications.** Sentinel detects prompt injection, unsafe tool
execution, excessive agent permissions, retrieval pipelines without tenancy
isolation, and model output flowing into `eval` — mapped to the OWASP Top 10 for
LLM Applications. A conventional SAST tool sees a template literal; Sentinel sees
an injection path into an agent that holds your production credentials.

**It integrates rather than reinvents.** Semgrep, Trivy, Gitleaks, Checkov,
osv-scanner, Syft and Hadolint are used when installed, through a normalizing
adapter layer. When they are absent, bundled scanners cover the same ground, so
coverage degrades gracefully instead of disappearing.

**It is honest about what it did not check.** Every report states which scanners
ran, which were skipped and why, which categories were never analyzed, and that
static analysis cannot prove reachability. A control is only marked *passing*
when the relevant domain was actually scanned.

**Explanations work offline.** The default analyst is a curated knowledge base:
deterministic, reviewed, free, and reproducible. Point it at OpenRouter and the
prose gets more specific to your code — but the fixes stay reviewed rather than
generated, and prioritization stays arithmetic so you can audit the ranking.

---

## Contents

- [Quick start](#quick-start)
- [What it finds](#what-it-finds)
- [Architecture](#architecture)
- [Scanner integrations](#scanner-integrations)
- [Configuration](#configuration)
- [API](#api)
- [CLI](#cli)
- [CI integration](#ci-integration)
- [Extending](#extending)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Quick start

Requires **Node 22.5+** (for the built-in SQLite driver) and **pnpm**.

```bash
git clone https://github.com/itsshreyasbhardwaj-design/sentinel-ai.git
cd sentinel-ai
pnpm install
pnpm build:packages
```

### Scan from the command line

```bash
pnpm scan ./path/to/your/repo
```

```
  your-app
  248 files · typescript 78.2% · python 21.8% · 1.4s

  ████████████████░░░░░░░░  71/100  Grade C  moderate

  2 critical  ·  9 high  ·  14 medium  ·  6 low

  code            ███████████░░░░░  68  2 critical, 4 high findings detected.
  dependencies    █████████████░░░  81  3 high, 2 medium findings detected.
  secrets         ████████████████ 100  No issues detected.
  aiSafety        ██████████░░░░░░  62  5 high, 1 medium findings detected.

  Top findings

  critical Agent tool executes shell commands or arbitrary code
           src/agent.py:24  ·  priority #1
           → Replace general tools with narrow ones
```

### Run the dashboard

```bash
pnpm dev          # http://localhost:3000
```

No configuration required. SQLite, an in-memory cache, an in-process job queue
and the knowledge-base analyst are wired up automatically, and `/api/health`
tells you exactly which implementations are active.

---

## What it finds

| Domain | Coverage |
| --- | --- |
| **Static analysis** | Injection (SQL, command, code, LDAP, NoSQL, XXE), XSS, SSRF, path traversal, deserialization, weak cryptography, predictable randomness, disabled TLS verification, JWT bypass, prototype pollution, open redirect — across TypeScript, JavaScript, Python, Java, Go, Rust, C#, PHP |
| **AI security** | Direct and indirect prompt injection, unsafe model-output handling, agent tools with shell access, missing human approval, over-privileged agent credentials, secrets and PII in prompts, vector search without tenancy filters, corpus poisoning, unpinned models and MCP servers, unbounded token consumption |
| **Dependencies** | npm, PyPI, Go, Cargo, Maven, Composer, NuGet, RubyGems — matched against a bundled advisory snapshot, augmented by OSV.dev when network access is enabled |
| **Secrets** | 20+ provider signatures (AWS, GitHub, Stripe, OpenAI, Anthropic, Slack, Google, Supabase, …) plus Shannon-entropy analysis with placeholder filtering |
| **Containers** | Dockerfile and Compose: root execution, floating tags, build-time secrets, `curl | sh`, privileged mode, docker socket mounts |
| **Infrastructure** | Terraform and Kubernetes: public ingress, unencrypted storage, public buckets, wildcard IAM, privileged pods, host namespaces |
| **Configuration** | Committed `.env` files, GitHub Actions script injection, `pull_request_target` misuse, unpinned actions, permissive CSP |
| **Licenses** | SPDX classification by obligation class, flagging copyleft and source-available licences that conflict with proprietary distribution |
| **SBOM** | CycloneDX 1.5 generation |

Everything is mapped to **CWE**, **OWASP Top 10 2021**, **OWASP LLM Top 10 2025**,
**CWE Top 25**, **NIST SSDF**, **SOC 2**, **PCI DSS 4.0**, **ISO 27001:2022** and
the **NIST AI RMF**.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  apps/web — Next.js App Router                                       │
│  Dashboard · REST API · SSE progress · GitHub webhooks               │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────┴──────────────────────────────────────┐
│  @sentinel/platform                                                  │
│  Storage (SQLite │ Postgres)   Cache (memory │ Redis)                │
│  Jobs (in-process │ Trigger)   Auth (dev │ Clerk)                    │
│  Rate limiting · AES-256-GCM secret encryption                       │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
┌───────┴────────┐   ┌──────────┴─────────┐   ┌─────────┴────────┐
│ @sentinel/     │   │ @sentinel/ai       │   │ @sentinel/       │
│ scanners       │   │                    │   │ reports          │
│                │   │ Knowledge base     │   │                  │
│ Registry       │   │   (offline, free)  │   │ SARIF 2.1.0      │
│ 9 native       │   │ OpenRouter         │   │ PDF · HTML · MD  │
│ 7 external     │   │   (optional)       │   │ CSV · JSON       │
│ Rule engine    │   │                    │   │                  │
│ Advisory DB    │   │ Explain            │   │ Compliance       │
│ SBOM           │   │ Prioritize         │   │ reports          │
│ Workspace      │   │ Remediate          │   │                  │
└───────┬────────┘   └──────────┬─────────┘   └─────────┬────────┘
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    │ @sentinel/core        │
                    │ Domain model          │
                    │ Severity · Scoring    │
                    │ Fingerprints          │
                    │ Compliance frameworks │
                    │ Redacting logger      │
                    └───────────────────────┘
```

### Design decisions worth knowing

**Every integration is optional.** Postgres, Redis, Clerk, Trigger.dev and
OpenRouter each have a zero-configuration default. `/api/health` reports which is
active, so a deployment that silently fell back is visible rather than surprising.

**Findings have stable fingerprints.** Identity is hashed from rule, path,
normalized snippet and component — deliberately *not* line numbers. Adding an
import at the top of a file does not resolve-and-reintroduce every finding below
it, which is what makes trend tracking and "introduced by this PR" meaningful.

**Unanalyzed is not the same as clean.** Score categories that were not scanned
are excluded from the overall score rather than contributing a free 100, and
compliance controls report `needs-review` rather than `pass`.

**Scores use diminishing returns.** The fortieth medium finding tells you much
less than the first. Without that, every large legacy repository scores zero and
the number stops being actionable.

**Suppression is first-class.** Inline `sentinel-disable-next-line` markers are
honoured, as are existing `nosemgrep` and `# nosec` annotations — a team that has
already triaged a false positive should not have to do it twice.

---

## Scanner integrations

Sentinel prefers best-in-class tools when they are installed and falls back to
bundled implementations when they are not.

| Tool | Domain | Supersedes | Install |
| --- | --- | --- | --- |
| [Semgrep](https://semgrep.dev) | SAST | `native-sast` | `pip install semgrep` |
| [Trivy](https://trivy.dev) | Dependencies, IaC, secrets | `native-dependencies`, `native-iac` | `brew install trivy` |
| [Gitleaks](https://gitleaks.io) | Secrets (incl. git history) | — (complements) | `brew install gitleaks` |
| [osv-scanner](https://google.github.io/osv-scanner/) | Dependencies | `native-dependencies` | `brew install osv-scanner` |
| [Checkov](https://checkov.io) | IaC | `native-iac` | `pip install checkov` |
| [Hadolint](https://github.com/hadolint/hadolint) | Containers | `native-container` | `brew install hadolint` |
| [Syft](https://github.com/anchore/syft) | SBOM | `native-sbom` | `brew install syft` |

Check what is detected on your machine:

```bash
pnpm scan --list-scanners
```

Gitleaks deliberately does *not* supersede the bundled secret scanner: the two
use different rule sets, and agreement between independent scanners raises a
finding's confidence.

---

## Configuration

Copy `.env.example` to `.env` — every value has a working default.

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | — | Postgres/Supabase. Omit to use SQLite. |
| `SQLITE_PATH` | `.sentinel/sentinel.db` | SQLite location |
| `REDIS_URL` | — | Shared cache. Omit for in-memory. |
| `CLERK_SECRET_KEY` + `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` | — | Authentication. **Required in production.** |
| `OPENROUTER_API_KEY` | — | Model-generated explanations |
| `AI_PROVIDER` | `auto` | `auto` · `knowledge-base` · `openrouter` |
| `AI_MAX_EXPLANATIONS` | `50` | Explained findings per scan |
| `ALLOW_NETWORK_SCANNERS` | `false` | Permit OSV.dev advisory lookups |
| `ENCRYPTION_KEY` | — | AES-256-GCM key for stored tokens. **Required in production.** |
| `GITHUB_TOKEN` / `GITHUB_WEBHOOK_SECRET` | — | Private repos and webhooks |
| `RATE_LIMIT_SCAN_MAX` | `10` | Scans per hour per caller |
| `SCAN_MAX_FILES` | `25000` | Hard file ceiling |
| `MAX_UPLOAD_BYTES` | `104857600` | Upload limit |

Starting with `NODE_ENV=production` and no authentication provider **fails at
startup** rather than serving an unauthenticated security dashboard.

---

## API

All endpoints require authentication (except `/api/health`), are rate limited,
and return typed errors as `{ "error": { "code", "message" } }`.

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/api/scans` | Start a scan. Returns `202` with a job id. |
| `GET` | `/api/scans?jobId=…` | Poll job status |
| `GET` | `/api/scans` | List scans |
| `GET` | `/api/scans/{id}` | Full result with AI analysis |
| `DELETE` | `/api/scans/{id}` | Delete a scan |
| `GET` | `/api/scans/{id}/stream` | Server-sent progress events |
| `GET` | `/api/scans/{id}/findings` | Filter, sort, paginate; includes facet counts |
| `GET` | `/api/scans/{id}/findings/{findingId}` | One finding with a remediation plan |
| `PATCH` | `/api/scans/{id}/findings/{findingId}` | Triage a finding |
| `GET` | `/api/scans/{id}/stats` | Aggregates |
| `GET` | `/api/scans/{id}/compliance` | Framework assessments |
| `GET` | `/api/scans/{id}/export?format=…` | `json` `sarif` `csv` `markdown` `html` `pdf` |
| `GET` | `/api/projects` | Projects with posture and trend |
| `GET` | `/api/projects/{id}/trend` | Score history |
| `GET` | `/api/scanners` | Scanner availability |
| `POST` | `/api/upload` | Scan an uploaded ZIP |
| `POST` | `/api/webhooks/github` | HMAC-verified push and pull-request events |
| `GET` | `/api/health` | Component status and configuration warnings |

```bash
curl -X POST http://localhost:3000/api/scans \
  -H 'content-type: application/json' \
  -d '{"target":{"type":"github","owner":"acme","repo":"web","ref":"main"}}'
```

Full reference: [`docs/api.md`](docs/api.md).

---

## CLI

```bash
sentinel <path|owner/repo|archive.zip> [options]
```

| Option | Description |
| --- | --- |
| `--kinds <list>` | Restrict analysis domains |
| `--format <list>` | Export formats |
| `--output <dir>` | Where to write reports |
| `--fail-on <severity>` | Exit `1` when a finding meets this threshold |
| `--network` | Enable OSV.dev lookups |
| `--list-scanners` | Show detected tools |
| `--json` | Machine-readable output |

Exit codes: `0` clean · `1` threshold breached · `2` scan failed.

---

## CI integration

```yaml
name: Security
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required to upload SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - uses: pnpm/action-setup@v4

      - run: pnpm install --frozen-lockfile && pnpm build:packages

      - name: Scan
        run: pnpm scan . --fail-on high --format sarif --output ./reports

      - name: Upload to GitHub code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ./reports
```

Findings then appear inline on the pull request, tracked across commits by their
stable fingerprints.

---

## Extending

A scanner is one object. Register it and it participates in selection,
availability reporting, scoring, compliance mapping and every export format —
nothing else changes.

```ts
import { register, type Scanner } from '@sentinel/scanners';

export const myScanner: Scanner = {
  id: 'my-scanner',
  name: 'My Scanner',
  kind: 'sast',
  origin: 'native',
  description: 'Detects the thing my team keeps getting wrong.',

  async isAvailable() {
    return { available: true };
  },

  async scan(ctx) {
    const findings = [];
    for (const file of ctx.files) {
      const content = await ctx.readFile(file);
      if (content.includes('DANGEROUS_PATTERN')) {
        findings.push({
          ruleId: 'my-rule',
          title: 'Dangerous pattern detected',
          severity: 'high',
          kind: 'sast',
          location: { path: file.path, startLine: 1 },
          taxonomy: { cwe: ['CWE-693'] },
        });
      }
    }
    return findings;
  },
};

register(myScanner);
```

Adding a detection rule to the bundled engine is smaller still — see
[`docs/extending.md`](docs/extending.md).

---

## Roadmap

- [ ] Reachability analysis, to separate vulnerable-and-called from
      vulnerable-and-dead
- [ ] Automated fix pull requests for dependency upgrades
- [ ] IDE extension with inline findings
- [ ] Additional languages: Ruby, Kotlin, Swift, Elixir
- [ ] Runtime agent instrumentation for AI applications
- [ ] Signed attestations (SLSA provenance) for scan results
- [ ] Historical advisory replay: "was this vulnerable at release time?"

---

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
pnpm verify   # format, lint, typecheck, unit tests, production build
pnpm test:e2e # Playwright end-to-end suite
```

New detection rules need a fixture in `fixtures/` and a test asserting they fire.
Rules are tuned for **precision over recall**: a scanner that cries wolf gets
muted, and a muted scanner finds nothing.

---

## Security

Sentinel handles untrusted repositories and uploads by design. Archive
extraction, subprocess execution and repository walking are covered by a
dedicated regression suite (`packages/scanners/src/security.test.ts`).

To report a vulnerability, see [SECURITY.md](SECURITY.md). Please do not open a
public issue.

---

## License

[MIT](LICENSE) © Sentinel AI contributors
