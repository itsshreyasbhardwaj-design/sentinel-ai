# Deployment

Sentinel runs three ways. Pick the one that matches how you want to use it.

---

## 1. CLI in CI (recommended starting point)

No server, no database, no state. The scanner runs in your pipeline and writes
reports as artifacts.

```yaml
- run: pnpm install --frozen-lockfile && pnpm build:packages
- run: pnpm scan . --fail-on high --format sarif --output ./reports
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ./reports
```

Findings then appear inline on the pull request. Because fingerprints are stable
across commits, GitHub tracks each alert rather than re-reporting it.

---

## 2. Self-hosted dashboard

```bash
pnpm install
pnpm build
pnpm --filter @sentinel/web start
```

With no configuration this uses SQLite, an in-memory cache and an in-process job
queue. That is a genuinely reasonable production setup for a single team on a
single instance.

### Before exposing it beyond localhost

```bash
NODE_ENV=production
ENCRYPTION_KEY=$(openssl rand -hex 32)
CLERK_SECRET_KEY=sk_live_...
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_...
APP_URL=https://sentinel.yourcompany.com
```

Sentinel **refuses to start** in production without an auth provider and an
encryption key. That is deliberate: an unauthenticated security dashboard leaks
every finding for every repository you have scanned.

### When to add the optional services

| Add | When |
| --- | --- |
| `DATABASE_URL` (Postgres) | More than one instance, or you want backups you already know how to run |
| `REDIS_URL` | More than one instance — the cache and rate limiter must be shared |
| `TRIGGER_SECRET_KEY` | Scans must survive a restart |
| `OPENROUTER_API_KEY` | You want explanations tailored to your specific code |
| `ALLOW_NETWORK_SCANNERS=true` | You want live OSV.dev advisories rather than the bundled snapshot |

Confirm what is actually active:

```bash
curl https://sentinel.yourcompany.com/api/health
```

---

## 3. Vercel

The dashboard deploys to Vercel unchanged, with two caveats worth understanding
before you rely on it.

```bash
vercel --prod
```

Required environment: `DATABASE_URL`, `REDIS_URL`, `CLERK_SECRET_KEY`,
`NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY`, `ENCRYPTION_KEY`, `APP_URL`.

**Caveat 1 — storage must be Postgres.** SQLite writes to a local file; serverless
instances do not share one.

**Caveat 2 — scans need a durable queue.** The in-process queue lives in the
memory of one instance, and serverless functions have execution limits well below
a large scan. Either configure Trigger.dev, or run scans from CI and use the
dashboard purely for reporting. The second option is simpler and works well.

---

## Docker

```dockerfile
FROM node:22-alpine AS base
RUN corepack enable

FROM base AS deps
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages ./packages
COPY apps ./apps
RUN pnpm install --frozen-lockfile

FROM base AS build
WORKDIR /app
COPY --from=deps /app ./
RUN pnpm build

FROM base AS runtime
WORKDIR /app
# Never run as root: a container escape should not start with uid 0.
RUN addgroup -S sentinel && adduser -S sentinel -G sentinel
COPY --from=build --chown=sentinel:sentinel /app ./
USER sentinel
EXPOSE 3000
CMD ["pnpm", "--filter", "@sentinel/web", "start"]
```

Install the optional external scanners in the image to widen coverage:

```dockerfile
RUN apk add --no-cache git && \
    pip install --no-cache-dir semgrep checkov
```

Git is required for GitHub targets.

---

## Operational notes

**Storage growth.** Each scan stores its full result as JSON. A large repository
with a few hundred findings is on the order of a megabyte. Prune old scans if
that matters; score history is kept separately and survives.

**Scan concurrency.** `SCAN_CONCURRENCY` bounds file-level parallelism within a
scanner. The default of 8 suits a 2-4 core instance. Raising it past core count
buys little because the bottleneck is IO.

**Rate limits.** `RATE_LIMIT_SCAN_MAX` defaults to 10/hour, which is right for a
shared instance and wrong for a CI runner. Raise it for the latter.

**Backups.** SQLite: back up `SQLITE_PATH` and its `-wal` file together. Postgres:
whatever you already do.

**Monitoring.** `GET /api/health` returns `warnings` for any component that fell
back to a weaker default. Alert on that array being non-empty in production.
