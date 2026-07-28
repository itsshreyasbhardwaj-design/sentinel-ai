# REST API

Base URL: `{APP_URL}/api`

All endpoints except `/health` require authentication. Errors are returned as:

```json
{ "error": { "code": "VALIDATION_ERROR", "message": "…", "details": [] } }
```

| Code | Status | Meaning |
| --- | --- | --- |
| `VALIDATION_ERROR` | 400 | Request failed schema validation |
| `UNAUTHORIZED` | 401 | No valid session or token |
| `FORBIDDEN` | 403 | Authenticated but not permitted |
| `NOT_FOUND` | 404 | Missing, or not visible to you |
| `CONFLICT` | 409 | Resource already exists |
| `PAYLOAD_TOO_LARGE` | 413 | Upload exceeds the limit |
| `UNSUPPORTED_TARGET` | 422 | Target could not be materialized |
| `RATE_LIMITED` | 429 | Budget exhausted; see `retry-after` |
| `SCANNER_FAILURE` | 502 | An external scanner failed |
| `TIMEOUT` | 504 | Operation exceeded its deadline |

Rate limits are returned on every response as `ratelimit-limit`,
`ratelimit-remaining` and `ratelimit-reset`.

---

## Scans

### `POST /api/scans`

Starts a scan. Returns immediately — a scan can take minutes, which is longer
than most proxies will hold a connection open.

```json
{
  "target": { "type": "github", "owner": "acme", "repo": "web", "ref": "main" },
  "name": "Optional project name",
  "options": {
    "kinds": ["sast", "secrets", "ai-security"],
    "allowNetwork": false,
    "failOn": "high"
  }
}
```

Target forms:

```json
{ "type": "github", "owner": "acme", "repo": "web", "ref": "main", "token": "ghp_…" }
{ "type": "local",  "path": "/absolute/path" }
{ "type": "archive", "archivePath": "/tmp/upload.zip" }
```

`local` targets are refused in production, so an API client cannot use Sentinel
to read arbitrary host paths.

**`202 Accepted`**

```json
{
  "jobId": "job_a1b2c3…",
  "status": "queued",
  "project": { "id": "proj_…", "name": "acme/web", "slug": "acme-web" },
  "links": { "progress": "/api/scans/{jobId}/stream" }
}
```

Rate limit: `RATE_LIMIT_SCAN_MAX` per `RATE_LIMIT_SCAN_WINDOW_MS` (default 10/hour).

### `GET /api/scans?jobId={jobId}`

Poll a job.

```json
{
  "jobId": "job_…",
  "status": "running",
  "progress": {
    "percent": 46,
    "phase": "scanning",
    "message": "Running Sentinel Dependency Scanner",
    "completedScanners": ["native-sast", "native-secrets"],
    "totalScanners": 9,
    "findingsSoFar": 31
  }
}
```

On completion, `result.scanId` holds the stored scan.

### `GET /api/scans/{scanId}/stream`

Server-sent events. Preferred over polling.

```
event: status
data: {"jobId":"job_…","status":"running"}

event: progress
data: {"percent":46,"phase":"scanning","message":"Running Sentinel SAST",…}

event: done
data: {"jobId":"job_…","status":"completed","result":{"scanId":"scan_…"}}
```

A keepalive comment is sent every 15 seconds so intermediate proxies do not close
an idle connection.

```js
const source = new EventSource(`/api/scans/${jobId}/stream`);
source.addEventListener('progress', (e) => console.log(JSON.parse(e.data)));
source.addEventListener('done', (e) => {
  source.close();
  location.href = `/scans/${JSON.parse(e.data).result.scanId}`;
});
```

### `GET /api/scans/{scanId}`

The full result, plus the AI summary and priority ranking.

### `GET /api/scans`

`?projectId=` `?limit=` `?offset=` — paginated list, newest first.

### `DELETE /api/scans/{scanId}`

---

## Findings

### `GET /api/scans/{scanId}/findings`

| Parameter | Description |
| --- | --- |
| `severity` | `critical` `high` `medium` `low` `info` — repeat or comma-separate |
| `kind` | `sast` `dependencies` `secrets` `container` `iac` `license` `sbom` `config` `ai-security` |
| `status` | `open` `triaged` `fixed` `accepted-risk` `false-positive` |
| `scanner` | Filter by producing scanner |
| `search` | Free text over title, rule, path and package |
| `path` | Substring match on file path |
| `suppressed` | `true` / `false` |
| `limit` | Default 50, max 500 |
| `offset` | Default 0 |

Results are ordered by AI priority when available, falling back to risk score.
The response includes **facets** — counts over the *unfiltered* set — so a filter
UI can show what is available rather than only what is selected.

```json
{
  "items": [ { "id": "fnd_…", "severity": "critical", "priority": { "rank": 1 } } ],
  "total": 94,
  "facets": {
    "severity": { "critical": 45, "high": 29 },
    "kind": { "sast": 33, "ai-security": 14 }
  }
}
```

### `GET /api/scans/{scanId}/findings/{findingId}`

Returns the finding, its priority, and a **remediation plan** with ordered steps,
example code, risks and verification instructions.

### `PATCH /api/scans/{scanId}/findings/{findingId}`

```json
{ "status": "false-positive", "note": "Parameterized by the ORM one frame up" }
```

`accepted-risk` and `false-positive` suppress the finding, which removes it from
scoring and compliance assessment.

---

## Analysis

### `GET /api/scans/{scanId}/stats`

Aggregates by kind, scanner, file and rule, plus scores, coverage and the top
priorities.

### `GET /api/scans/{scanId}/compliance`

`?framework=` to select; omit for all.

Available: `owasp-top-10-2021`, `owasp-llm-top-10-2025`, `cwe-top-25`,
`nist-ssdf-1.1`, `soc2-cc`, `pci-dss-4.0`, `iso-27001-2022-a8`,
`nist-ai-rmf-1.0`.

```json
{
  "analyzedKinds": ["sast", "secrets", "ai-security"],
  "reports": [{
    "frameworkName": "OWASP Top 10",
    "coveragePercent": 60,
    "passed": 3, "failed": 2, "needsReview": 5,
    "assessments": [{
      "controlId": "A03:2021",
      "status": "fail",
      "worstSeverity": "critical",
      "findingIds": ["fnd_…"],
      "evidence": "4 finding(s) map to this control; highest severity critical."
    }]
  }]
}
```

A control is `needs-review` — never `pass` — when the scan did not cover the
domain required to evaluate it.

### `GET /api/scans/{scanId}/export?format={format}`

`json` · `sarif` · `csv` · `markdown` · `html` · `pdf`

Optional: `framework` (repeatable), `maxFindings`.

Returned as an attachment with a sanitized filename. HTML reports are
self-contained with no external references.

---

## Projects

| Endpoint | Description |
| --- | --- |
| `GET /api/projects` | Projects with latest posture and trend |
| `POST /api/projects` | Create a project |
| `GET /api/projects/{id}` | Project, latest scan, history |
| `DELETE /api/projects/{id}` | Delete, cascading to scans |
| `GET /api/projects/{id}/trend` | Score history and trend direction |

---

## Upload

### `POST /api/upload`

`multipart/form-data` with a `file` field. Optional `name` and `projectId`.

Validated on three independent axes — declared size, filename, and magic bytes —
then again per entry during extraction for path traversal and compression ratio.

Returns `202` with a `jobId`, same as `POST /api/scans`.

---

## Webhooks

### `POST /api/webhooks/github`

Verifies `x-hub-signature-256` with a constant-time comparison against
`GITHUB_WEBHOOK_SECRET`. Handles `push` (branch pushes only) and `pull_request`
(`opened`, `synchronize`, `reopened`). Deliveries are deduplicated by
`x-github-delivery`.

Always returns `200` on internal failure — a non-2xx makes GitHub retry and
eventually disable the webhook, which is worse than a missed scan.

---

## Operations

### `GET /api/scanners`

Which analysis engines this installation can run, and why any are unavailable.

### `GET /api/health`

Unauthenticated, for load balancers.

```json
{
  "status": "ok",
  "components": {
    "storage": "sqlite", "cache": "memory", "queue": "in-process",
    "auth": "development", "authEnforcing": false,
    "aiProvider": "knowledge-base", "networkScanners": false
  },
  "warnings": [
    "Authentication is not enforced. Configure Clerk before exposing this deployment."
  ]
}
```

The `warnings` array is the important part: it makes a deployment that silently
fell back to a weaker configuration visible.
