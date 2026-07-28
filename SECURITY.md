# Security Policy

Sentinel AI processes untrusted input by design: it clones repositories it has
never seen, extracts archives chosen entirely by the uploader, and runs
third-party scanner binaries over the result. We take reports about that surface
seriously.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

Pre-1.0, only the latest minor version receives security fixes.

## Reporting a vulnerability

**Please do not open a public issue.**

Use [GitHub's private vulnerability reporting](https://github.com/itsshreyasbhardwaj-design/sentinel-ai/security/advisories/new)
for the repository. If that is unavailable to you, open a public issue containing
only the words "security report — please contact me" and no technical detail, and
a maintainer will arrange a private channel.

Please include, as far as you are able:

- The affected component and version or commit
- A description of the vulnerability and its impact
- Steps to reproduce, ideally with a minimal proof of concept
- Any suggested remediation

### What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement | within 48 hours |
| Initial assessment | within 5 working days |
| Fix for critical issues | within 14 days |
| Fix for other issues | next release |

We will keep you informed as the fix progresses, credit you in the advisory
unless you prefer otherwise, and coordinate disclosure timing with you.

## Responsible disclosure

We ask that you:

- Give us reasonable time to fix the issue before public disclosure — 90 days is
  the default, and we will usually be much faster.
- Avoid accessing, modifying or deleting data that is not yours.
- Do not degrade service for other users while testing.
- Test only against your own deployment, never someone else's.

We commit that we will:

- Not pursue legal action against good-faith research that follows this policy.
- Respond promptly and keep you updated.
- Credit you publicly if you want to be credited.

## Threat model

Sentinel's own attack surface is where reports are most valuable. The controls
below exist deliberately and are covered by
`packages/scanners/src/security.test.ts` — a regression in any of them is a
vulnerability, not a bug.

### Untrusted archives

Uploaded ZIPs are attacker-controlled byte for byte.

- **Path traversal (zip slip)** — every entry is checked twice: by name shape and
  by resolved path. Absolute paths, `..` segments, Windows drive paths,
  backslash traversal and null bytes are all rejected.
- **Zip bombs** — per-entry size, total uncompressed size, entry count and
  compression ratio are all bounded. ZIP64 is refused rather than partially
  supported.
- **Content sniffing** — magic bytes are checked; the extension and
  `Content-Type` are not trusted.

### Untrusted repositories

- **Command injection** — external tools are invoked with `execFile` and an
  argument array. No shell is ever spawned. Git refs are validated against a
  strict character set and rejected if they could be read as a flag.
- **Environment isolation** — child processes receive only `PATH`, `HOME` and
  `LANG`. A third-party scanner never sees Sentinel's database URL or API keys.
- **Symlink escapes** — the repository walker never follows symlinks, so a link
  to `/` cannot walk the disk and a link out of the repository cannot exfiltrate.
- **Resource exhaustion** — file count, file size, line length and total scan
  time are all bounded.

### Data handling

- **Secrets are masked at the source.** A detected credential is masked inside
  the scanner before it becomes a finding, so it never reaches the database,
  reports, exports or logs.
- **Logs redact.** The logger strips sensitive keys and known credential shapes
  at the boundary rather than trusting call sites.
- **No host paths in findings.** Findings carry repository-relative paths only,
  enforced by test.
- **Stored tokens are encrypted** with AES-256-GCM using a scrypt-derived
  per-value key.

### Application security

- **Authentication is mandatory in production.** Starting with
  `NODE_ENV=production` and no auth provider fails at startup rather than
  serving an unauthenticated dashboard.
- **Ownership is checked on every read**, and refused as `404` so resource
  existence is not disclosed.
- **Rate limiting** applies per bucket, with scan creation limited far more
  tightly than reads.
- **Webhook signatures** are verified with a constant-time comparison.
- **API keys** are stored hashed and compared in constant time.
- **CSV exports** neutralize formula injection, so an exported finding title
  cannot execute when opened in a spreadsheet.
- **HTML reports** are served as attachments and contain no external references.

## Out of scope

- Findings Sentinel does not detect. Missing coverage is a feature request, not
  a vulnerability — please open a normal issue.
- False positives, for the same reason.
- Vulnerabilities in third-party scanners. Report those upstream; we will bump
  the integration once fixed.
- Denial of service that requires credentials the attacker should not have.
- Issues that only affect a deployment which has explicitly disabled a
  documented control.
