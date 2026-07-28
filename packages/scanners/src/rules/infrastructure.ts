import type { Rule } from '../types.js';
import { notInComment } from './engine.js';

/**
 * Infrastructure-as-code, container and application configuration rules.
 *
 * Split by file shape rather than language, since these formats are matched by
 * path (`Dockerfile`, `*.tf`, `k8s/*.yaml`) instead of by extension-derived
 * language.
 */

const REF = (id: number) => `https://cwe.mitre.org/data/definitions/${id}.html`;

/* ------------------------------------------------------------------ */
/* Containers                                                          */
/* ------------------------------------------------------------------ */

export const CONTAINER_RULES: Rule[] = [
  {
    id: 'docker-run-as-root',
    title: 'Container image runs as root',
    description:
      'No `USER` instruction means the container process runs as uid 0. A container escape or an exploited process then starts with root privileges.',
    severity: 'medium',
    kind: 'container',
    confidence: 'medium',
    pathPatterns: ['**/Dockerfile', '**/Dockerfile.*', '**/*.dockerfile', '**/Containerfile'],
    patterns: [/^\s*FROM\s+/i],
    // Only fires on the final stage of a multi-stage build that never sets USER.
    validate: (match) => {
      const lines = match.lines;
      const fromIndices = lines
        .map((line, i) => (/^\s*FROM\s+/i.test(line) ? i : -1))
        .filter((i) => i >= 0);
      const lastFrom = fromIndices[fromIndices.length - 1];
      if (lastFrom !== match.lineNumber - 1) return false;
      const finalStage = lines.slice(lastFrom);
      return !finalStage.some((line) => /^\s*USER\s+(?!root\b|0\b)/i.test(line));
    },
    taxonomy: {
      cwe: ['CWE-250'],
      owaspTop10: ['A05:2021-Security Misconfiguration'],
      references: [{ title: 'CWE-250: Execution with Unnecessary Privileges', url: REF(250) }],
    },
    remediationHint:
      'Create an unprivileged user and switch to it: `RUN adduser -D app` then `USER app`.',
  },
  {
    id: 'docker-latest-tag',
    title: 'Base image uses a floating tag',
    description:
      '`latest` (or no tag) makes builds non-reproducible and silently pulls in changes, including regressions and newly vulnerable packages.',
    severity: 'low',
    kind: 'container',
    confidence: 'high',
    pathPatterns: ['**/Dockerfile', '**/Dockerfile.*', '**/*.dockerfile', '**/Containerfile'],
    patterns: [/^\s*FROM\s+(?!scratch\b)[^\s:@]+(?::latest)?\s*(?:AS\s+\w+)?\s*$/i],
    taxonomy: {
      cwe: ['CWE-1104'],
      owaspTop10: ['A06:2021-Vulnerable and Outdated Components'],
      references: [
        { title: 'CWE-1104: Use of Unmaintained Third Party Components', url: REF(1104) },
      ],
    },
    remediationHint: 'Pin by digest: `FROM node:22.11.0-alpine@sha256:…`.',
  },
  {
    id: 'docker-secret-in-build',
    title: 'Secret passed through a build argument or environment variable',
    description:
      'Values in `ARG`/`ENV` are baked into image layers and readable by anyone who can pull the image, even if a later layer deletes them.',
    severity: 'high',
    kind: 'container',
    confidence: 'medium',
    pathPatterns: ['**/Dockerfile', '**/Dockerfile.*', '**/*.dockerfile', '**/Containerfile'],
    patterns: [
      /^\s*(?:ARG|ENV)\s+\w*(?:PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL)\w*\s*=?\s*\S+/i,
    ],
    excludePatterns: [/=\s*$/, /=\s*["']?\s*["']?$/],
    taxonomy: {
      cwe: ['CWE-798', 'CWE-522'],
      owaspTop10: ['A05:2021-Security Misconfiguration'],
      references: [{ title: 'CWE-522: Insufficiently Protected Credentials', url: REF(522) }],
    },
    remediationHint:
      'Use BuildKit secret mounts (`RUN --mount=type=secret,id=npmrc …`) or inject at runtime.',
  },
  {
    id: 'docker-curl-pipe-shell',
    title: 'Remote script piped directly into a shell',
    description:
      'Downloading and executing a script in one step means the build trusts whatever the server returns at that moment, with no integrity check.',
    severity: 'high',
    kind: 'container',
    confidence: 'high',
    pathPatterns: ['**/Dockerfile', '**/Dockerfile.*', '**/Containerfile', '**/*.sh'],
    patterns: [/(?:curl|wget)[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b/],
    taxonomy: {
      cwe: ['CWE-494'],
      owaspTop10: ['A08:2021-Software and Data Integrity Failures'],
      references: [{ title: 'CWE-494: Download of Code Without Integrity Check', url: REF(494) }],
    },
    remediationHint:
      'Download to a file, verify a published checksum or signature, then execute it.',
  },
  {
    id: 'docker-add-remote',
    title: 'ADD used with a remote URL',
    description:
      '`ADD` with a URL fetches over the network without verification and auto-extracts archives. `COPY` is the predictable choice.',
    severity: 'low',
    kind: 'container',
    confidence: 'high',
    pathPatterns: ['**/Dockerfile', '**/Dockerfile.*', '**/Containerfile'],
    patterns: [/^\s*ADD\s+https?:\/\//i],
    taxonomy: { cwe: ['CWE-494'] },
    remediationHint: 'Use `RUN curl -fsSL … && echo "<sha256>  file" | sha256sum -c` then `COPY`.',
  },
  {
    id: 'docker-privileged-compose',
    title: 'Container granted privileged mode or host namespaces',
    description:
      'Privileged containers and host namespace sharing remove the isolation boundary; a compromise of the process is a compromise of the host.',
    severity: 'critical',
    kind: 'container',
    confidence: 'high',
    pathPatterns: ['**/docker-compose*.y*ml', '**/compose*.y*ml'],
    patterns: [
      /^\s*privileged\s*:\s*true/i,
      /^\s*network_mode\s*:\s*["']?host/i,
      /^\s*pid\s*:\s*["']?host/i,
      /^\s*-\s*["']?\/var\/run\/docker\.sock/,
    ],
    taxonomy: {
      cwe: ['CWE-250'],
      owaspTop10: ['A05:2021-Security Misconfiguration'],
      references: [{ title: 'CWE-250: Execution with Unnecessary Privileges', url: REF(250) }],
    },
    remediationHint:
      'Drop privileged mode and grant only the specific capabilities required via `cap_add`.',
  },
];

/* ------------------------------------------------------------------ */
/* Kubernetes & Terraform                                              */
/* ------------------------------------------------------------------ */

export const IAC_RULES: Rule[] = [
  {
    id: 'k8s-privileged-container',
    title: 'Kubernetes container runs privileged or can escalate privileges',
    description:
      '`privileged: true` grants effectively all host capabilities; `allowPrivilegeEscalation: true` lets a process gain more privileges than its parent.',
    severity: 'critical',
    kind: 'iac',
    confidence: 'high',
    pathPatterns: ['**/*.yaml', '**/*.yml'],
    patterns: [/^\s*privileged\s*:\s*true/i, /^\s*allowPrivilegeEscalation\s*:\s*true/i],
    validate: (match) =>
      match.lines.some((line) =>
        /^\s*kind\s*:\s*(?:Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|ReplicaSet)/i.test(
          line,
        ),
      ),
    taxonomy: {
      cwe: ['CWE-250'],
      owaspTop10: ['A05:2021-Security Misconfiguration'],
      references: [{ title: 'CWE-250: Execution with Unnecessary Privileges', url: REF(250) }],
    },
    remediationHint:
      'Set `securityContext: { privileged: false, allowPrivilegeEscalation: false, runAsNonRoot: true }`.',
  },
  {
    id: 'k8s-host-namespace',
    title: 'Pod shares a host namespace',
    description:
      'Sharing the host network, PID or IPC namespace lets the pod observe and interfere with every other process on the node.',
    severity: 'high',
    kind: 'iac',
    confidence: 'high',
    pathPatterns: ['**/*.yaml', '**/*.yml'],
    patterns: [/^\s*host(?:Network|PID|IPC)\s*:\s*true/i],
    taxonomy: {
      cwe: ['CWE-668'],
      owaspTop10: ['A05:2021-Security Misconfiguration'],
      references: [{ title: 'CWE-668: Exposure of Resource to Wrong Sphere', url: REF(668) }],
    },
    remediationHint: 'Remove the host namespace flags and expose ports through a Service.',
  },
  {
    id: 'k8s-no-resource-limits',
    title: 'Container has no CPU or memory limits',
    description:
      'Without limits, one workload can consume the whole node, taking unrelated services down with it.',
    severity: 'low',
    kind: 'iac',
    confidence: 'low',
    pathPatterns: ['**/*.yaml', '**/*.yml'],
    patterns: [/^\s*-\s*name\s*:\s*\S+\s*$/],
    validate: (match) => {
      const isWorkload = match.lines.some((line) =>
        /^\s*kind\s*:\s*(?:Pod|Deployment|StatefulSet|DaemonSet)/i.test(line),
      );
      if (!isWorkload) return false;
      const hasImage = match.lines.some((line) => /^\s*image\s*:/i.test(line));
      return hasImage && !match.lines.some((line) => /^\s*limits\s*:/i.test(line));
    },
    taxonomy: {
      cwe: ['CWE-770'],
      references: [{ title: 'CWE-770: Allocation Without Limits', url: REF(770) }],
    },
    remediationHint: 'Set `resources.limits.cpu` and `resources.limits.memory` on every container.',
  },
  {
    id: 'k8s-secret-in-env',
    title: 'Secret value hardcoded in a manifest',
    description:
      'Literal credentials in a manifest end up in version control and in every cluster that applies it.',
    severity: 'critical',
    kind: 'iac',
    confidence: 'medium',
    pathPatterns: ['**/*.yaml', '**/*.yml'],
    patterns: [
      /^\s*(?:-\s*)?(?:value|password|token|secret|api[_-]?key)\s*:\s*["']?(?!\s*$)(?!.*(?:secretKeyRef|valueFrom|configMapKeyRef|\$\{|\{\{))[^\s"']{12,}/i,
    ],
    validate: (match) => /password|secret|token|key|credential/i.test(match.line),
    taxonomy: {
      cwe: ['CWE-798'],
      owaspTop10: ['A05:2021-Security Misconfiguration'],
      references: [{ title: 'CWE-798: Use of Hard-coded Credentials', url: REF(798) }],
    },
    remediationHint:
      'Reference a Secret via `valueFrom.secretKeyRef`, or use an external secrets operator.',
  },
  {
    id: 'terraform-public-ingress',
    title: 'Security group open to the entire internet',
    description:
      'A `0.0.0.0/0` ingress rule exposes the port to every host on the internet. On an administrative port this is a direct path to compromise.',
    severity: 'high',
    kind: 'iac',
    confidence: 'high',
    pathPatterns: ['**/*.tf', '**/*.tf.json', '**/*.hcl'],
    patterns: [/cidr_blocks\s*=\s*\[[^\]]*["']0\.0\.0\.0\/0["']/, /["']::\/0["']/],
    taxonomy: {
      cwe: ['CWE-284'],
      owaspTop10: ['A01:2021-Broken Access Control'],
      references: [{ title: 'CWE-284: Improper Access Control', url: REF(284) }],
    },
    remediationHint:
      'Restrict the CIDR to known ranges, or place the service behind a load balancer or bastion.',
  },
  {
    id: 'terraform-unencrypted-storage',
    title: 'Storage resource created without encryption',
    description:
      'Encryption at rest is explicitly disabled. Anyone with access to the underlying storage — including snapshots and backups — can read the data.',
    severity: 'high',
    kind: 'iac',
    confidence: 'high',
    pathPatterns: ['**/*.tf', '**/*.tf.json', '**/*.hcl'],
    patterns: [
      /encrypted\s*=\s*false/,
      /(?:storage_)?encrypted\s*=\s*false/,
      /skip_final_snapshot\s*=\s*true/,
    ],
    taxonomy: {
      cwe: ['CWE-311'],
      owaspTop10: ['A02:2021-Cryptographic Failures'],
      references: [{ title: 'CWE-311: Missing Encryption of Sensitive Data', url: REF(311) }],
    },
    remediationHint: 'Set `encrypted = true` and supply a customer-managed KMS key where required.',
  },
  {
    id: 'terraform-public-bucket',
    title: 'Object storage bucket is publicly accessible',
    description:
      'Public ACLs on a bucket expose every object to anonymous readers — the single most common cause of large-scale data exposure.',
    severity: 'critical',
    kind: 'iac',
    confidence: 'high',
    pathPatterns: ['**/*.tf', '**/*.tf.json', '**/*.hcl'],
    patterns: [
      /acl\s*=\s*["'](?:public-read|public-read-write|authenticated-read)["']/,
      /block_public_acls\s*=\s*false/,
      /restrict_public_buckets\s*=\s*false/,
    ],
    taxonomy: {
      cwe: ['CWE-284', 'CWE-200'],
      owaspTop10: ['A01:2021-Broken Access Control'],
      references: [{ title: 'CWE-284: Improper Access Control', url: REF(284) }],
    },
    remediationHint:
      'Keep every public-access block enabled and serve public assets through a CDN.',
  },
  {
    id: 'terraform-hardcoded-credentials',
    title: 'Provider credentials hardcoded in Terraform',
    description:
      'Credentials in `.tf` files are committed to version control and shared with everyone who can read the repository.',
    severity: 'critical',
    kind: 'iac',
    confidence: 'medium',
    pathPatterns: ['**/*.tf', '**/*.tf.json', '**/*.tfvars', '**/*.hcl'],
    patterns: [
      /\b(?:access_key|secret_key|password|token|client_secret)\s*=\s*["'][^"'${\s]{8,}["']/i,
    ],
    excludePatterns: [/var\.|data\.|local\.|env\(|\$\{/],
    taxonomy: {
      cwe: ['CWE-798'],
      references: [{ title: 'CWE-798: Use of Hard-coded Credentials', url: REF(798) }],
    },
    remediationHint: 'Source credentials from the provider environment or a secrets manager.',
  },
  {
    id: 'terraform-iam-wildcard',
    title: 'IAM policy grants wildcard actions or resources',
    description:
      '`"Action": "*"` on `"Resource": "*"` is full administrative access. Any compromise of the principal becomes a full account compromise.',
    severity: 'high',
    kind: 'iac',
    confidence: 'high',
    pathPatterns: ['**/*.tf', '**/*.json', '**/*.hcl'],
    // Quotes around the key are optional: HCL writes `Action = "*"` bare, while
    // an inline JSON policy writes `"Action": "*"`.
    patterns: [
      /["']?Action["']?\s*[:=]\s*\[?\s*["']\*["']/,
      /["']?Resource["']?\s*[:=]\s*\[?\s*["']\*["']/,
    ],
    validate: (match) => match.lines.some((line) => /policy|iam|statement/i.test(line)),
    taxonomy: {
      cwe: ['CWE-269'],
      owaspTop10: ['A01:2021-Broken Access Control'],
      references: [{ title: 'CWE-269: Improper Privilege Management', url: REF(269) }],
    },
    remediationHint:
      'Enumerate the specific actions and resource ARNs the principal genuinely needs.',
  },
];

/* ------------------------------------------------------------------ */
/* Application & CI configuration                                      */
/* ------------------------------------------------------------------ */

export const CONFIG_RULES: Rule[] = [
  {
    id: 'config-committed-env-file',
    title: 'Environment file committed to the repository',
    description:
      'A `.env` file holding real values in version control exposes every secret it contains to anyone with repository access, and to every fork and clone.',
    severity: 'high',
    kind: 'config',
    confidence: 'medium',
    pathPatterns: [
      '**/.env',
      '**/.env.local',
      '**/.env.production',
      '**/.env.prod',
      '**/.env.staging',
    ],
    patterns: [/^\s*[A-Z_][A-Z0-9_]*\s*=\s*\S{8,}/],
    excludePatterns: [/=\s*(?:changeme|your|example|xxx|placeholder|todo|<)/i],
    taxonomy: {
      cwe: ['CWE-538'],
      owaspTop10: ['A05:2021-Security Misconfiguration'],
      references: [
        {
          title: 'CWE-538: Insertion of Sensitive Information into Externally-Accessible File',
          url: REF(538),
        },
      ],
    },
    remediationHint:
      'Add `.env` to `.gitignore`, commit only `.env.example`, and rotate every value that was exposed.',
  },
  {
    id: 'config-ci-pull-request-target',
    title: 'Workflow uses pull_request_target with an untrusted checkout',
    description:
      '`pull_request_target` runs with repository secrets available. Checking out the PR head under that trigger executes attacker-controlled code with access to those secrets.',
    severity: 'critical',
    kind: 'config',
    confidence: 'high',
    pathPatterns: ['**/.github/workflows/*.y*ml'],
    patterns: [/^\s*(?:-\s*)?pull_request_target\s*:?/],
    validate: (match) =>
      match.lines.some((line) => /ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head/.test(line)),
    taxonomy: {
      cwe: ['CWE-829'],
      owaspTop10: ['A08:2021-Software and Data Integrity Failures'],
      references: [
        {
          title: 'CWE-829: Inclusion of Functionality from Untrusted Control Sphere',
          url: REF(829),
        },
      ],
    },
    remediationHint:
      'Use `pull_request` for untrusted code, or split into a privileged job that never checks out the PR head.',
  },
  {
    id: 'config-ci-unpinned-action',
    title: 'GitHub Action referenced by a mutable tag',
    description:
      'Tags can be moved. Pinning to a tag means a compromised or repointed action executes in your pipeline with your secrets.',
    severity: 'medium',
    kind: 'config',
    confidence: 'high',
    pathPatterns: ['**/.github/workflows/*.y*ml', '**/.github/actions/**/*.y*ml'],
    patterns: [/^\s*-?\s*uses\s*:\s*[\w.-]+\/[\w.-]+@(?:v?\d+(?:\.\d+)*|main|master|latest)\s*$/],
    excludePatterns: [/@[a-f0-9]{40}/],
    taxonomy: {
      cwe: ['CWE-829'],
      owaspTop10: ['A08:2021-Software and Data Integrity Failures'],
      references: [
        { title: 'CWE-1357: Reliance on Insufficiently Trustworthy Component', url: REF(1357) },
      ],
    },
    remediationHint: 'Pin to a full commit SHA: `uses: actions/checkout@8f4b7f8…`.',
  },
  {
    id: 'config-ci-script-injection',
    title: 'Untrusted GitHub context interpolated into a run step',
    description:
      'Interpolating `github.event.*` into a `run:` block splices attacker-controlled text into the shell script, which executes with runner privileges.',
    severity: 'critical',
    kind: 'config',
    confidence: 'high',
    pathPatterns: ['**/.github/workflows/*.y*ml'],
    patterns: [
      /\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|discussion|head_commit)\.[\w.]*(?:title|body|message|name|label|ref)/,
    ],
    taxonomy: {
      cwe: ['CWE-78', 'CWE-94'],
      owaspTop10: ['A03:2021-Injection'],
      references: [{ title: 'CWE-78: OS Command Injection', url: REF(78) }],
    },
    remediationHint:
      'Pass the value through an `env:` variable and reference it as `"$TITLE"` so the shell never parses it as code.',
  },
  {
    id: 'config-nextjs-ignore-errors',
    title: 'Build configured to ignore type or lint errors',
    description:
      'Suppressing type and lint errors at build time removes an entire class of pre-deployment checks, including the security lint rules.',
    severity: 'low',
    kind: 'config',
    confidence: 'high',
    pathPatterns: ['**/next.config.*', '**/nuxt.config.*', '**/vite.config.*'],
    patterns: [/ignoreBuildErrors\s*:\s*true/, /ignoreDuringBuilds\s*:\s*true/],
    validate: notInComment,
    taxonomy: {
      cwe: ['CWE-1127'],
      owaspTop10: ['A05:2021-Security Misconfiguration'],
    },
    remediationHint: 'Fix the underlying errors rather than disabling the check.',
  },
  {
    id: 'config-permissive-csp',
    title: 'Content Security Policy allows unsafe sources',
    description:
      '`unsafe-inline` and `unsafe-eval` defeat the main purpose of a CSP, leaving injected scripts free to execute.',
    severity: 'medium',
    kind: 'config',
    confidence: 'high',
    patterns: [
      /Content-Security-Policy[^\n]*(?:unsafe-inline|unsafe-eval)/i,
      /script-src[^;\n]*unsafe-eval/i,
    ],
    validate: notInComment,
    taxonomy: {
      cwe: ['CWE-1021'],
      owaspTop10: ['A05:2021-Security Misconfiguration'],
      references: [
        { title: 'CWE-1021: Improper Restriction of Rendered UI Layers', url: REF(1021) },
      ],
    },
    remediationHint: 'Use per-request nonces or hashes instead of `unsafe-inline`.',
  },
  {
    id: 'config-npm-ignore-scripts-disabled',
    title: 'Package install scripts are not restricted',
    description:
      'Lifecycle scripts run arbitrary code on install. In CI, one malicious transitive dependency executes with pipeline credentials.',
    severity: 'low',
    kind: 'config',
    confidence: 'low',
    pathPatterns: ['**/.npmrc'],
    patterns: [/ignore-scripts\s*=\s*false/],
    taxonomy: {
      cwe: ['CWE-829'],
      references: [
        {
          title: 'CWE-829: Inclusion of Functionality from Untrusted Control Sphere',
          url: REF(829),
        },
      ],
    },
    remediationHint:
      'Set `ignore-scripts=true` in CI and allowlist the few packages that genuinely need them.',
  },
];
