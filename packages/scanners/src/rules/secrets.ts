/**
 * Secret detection.
 *
 * Two complementary strategies:
 *
 *  1. **Provider patterns** — high-confidence, low-noise signatures for
 *     credentials with a recognizable shape (`ghp_…`, `AKIA…`). These are
 *     reported at high severity because a match is almost never wrong.
 *  2. **Entropy analysis** — catches the long tail of custom tokens assigned to
 *     suspicious variable names. Gated behind an entropy threshold *and* a
 *     placeholder filter, because this is where naive scanners generate the
 *     noise that gets them switched off.
 */

export interface SecretPattern {
  id: string;
  title: string;
  /** The credential issuer, e.g. `AWS`. Used in explanations. */
  provider: string;
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium';
  /** Minimum Shannon entropy the captured secret must exhibit. */
  minEntropy?: number;
  /** How to revoke this credential — the only step that actually matters. */
  revocation: string;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'aws-access-key-id',
    title: 'AWS access key ID',
    provider: 'AWS',
    pattern: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,
    severity: 'critical',
    revocation: 'Deactivate the key in IAM › Users › Security credentials, then delete it.',
  },
  {
    id: 'aws-secret-access-key',
    title: 'AWS secret access key',
    provider: 'AWS',
    pattern: /\baws_?secret_?access_?key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    severity: 'critical',
    minEntropy: 4.0,
    revocation: 'Rotate the associated access key pair in IAM immediately.',
  },
  {
    id: 'github-token',
    title: 'GitHub personal access token',
    provider: 'GitHub',
    pattern: /\b(gh[pousr]_[A-Za-z0-9]{36,255})\b/g,
    severity: 'critical',
    revocation: 'Revoke at github.com/settings/tokens.',
  },
  {
    id: 'github-fine-grained-token',
    title: 'GitHub fine-grained personal access token',
    provider: 'GitHub',
    pattern: /\b(github_pat_[A-Za-z0-9_]{60,})\b/g,
    severity: 'critical',
    revocation: 'Revoke at github.com/settings/tokens?type=beta.',
  },
  {
    id: 'gitlab-token',
    title: 'GitLab personal access token',
    provider: 'GitLab',
    pattern: /\b(glpat-[A-Za-z0-9_-]{20,})\b/g,
    severity: 'critical',
    revocation: 'Revoke in GitLab › User Settings › Access Tokens.',
  },
  {
    id: 'slack-token',
    title: 'Slack API token',
    provider: 'Slack',
    pattern: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g,
    severity: 'high',
    revocation: 'Revoke the token in the Slack app configuration and reinstall the app.',
  },
  {
    id: 'slack-webhook',
    title: 'Slack incoming webhook URL',
    provider: 'Slack',
    pattern:
      /(https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+)/g,
    severity: 'medium',
    revocation: 'Delete and recreate the webhook in the Slack app settings.',
  },
  {
    id: 'stripe-secret-key',
    title: 'Stripe secret key',
    provider: 'Stripe',
    pattern: /\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b/g,
    severity: 'critical',
    revocation: 'Roll the key in the Stripe dashboard › Developers › API keys.',
  },
  {
    id: 'openai-api-key',
    title: 'OpenAI API key',
    provider: 'OpenAI',
    pattern: /\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,})\b/g,
    severity: 'critical',
    revocation: 'Revoke at platform.openai.com/api-keys.',
  },
  {
    id: 'anthropic-api-key',
    title: 'Anthropic API key',
    provider: 'Anthropic',
    pattern: /\b(sk-ant-[A-Za-z0-9_-]{20,})\b/g,
    severity: 'critical',
    revocation: 'Revoke in the Anthropic Console › API keys.',
  },
  {
    id: 'google-api-key',
    title: 'Google API key',
    provider: 'Google',
    pattern: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
    severity: 'high',
    revocation:
      'Delete or restrict the key in Google Cloud Console › APIs & Services › Credentials.',
  },
  {
    id: 'google-oauth-client-secret',
    title: 'Google OAuth client secret',
    provider: 'Google',
    pattern: /\b(GOCSPX-[A-Za-z0-9_-]{20,})\b/g,
    severity: 'critical',
    revocation: 'Reset the client secret in Google Cloud Console › Credentials.',
  },
  {
    id: 'private-key',
    title: 'Private cryptographic key',
    provider: 'PKI',
    pattern: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----)/g,
    severity: 'critical',
    revocation:
      'Treat the key as compromised: reissue the certificate or key pair and revoke the old one.',
  },
  {
    id: 'jwt-token',
    title: 'JSON Web Token',
    provider: 'JWT',
    pattern: /\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/g,
    severity: 'medium',
    revocation: 'Rotate the signing key so every issued token is invalidated.',
  },
  {
    id: 'npm-token',
    title: 'npm access token',
    provider: 'npm',
    pattern: /\b(npm_[A-Za-z0-9]{36})\b/g,
    severity: 'high',
    revocation: 'Revoke at npmjs.com/settings/~/tokens.',
  },
  {
    id: 'sendgrid-api-key',
    title: 'SendGrid API key',
    provider: 'SendGrid',
    pattern: /\b(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b/g,
    severity: 'high',
    revocation: 'Delete the key in SendGrid › Settings › API Keys.',
  },
  {
    id: 'twilio-api-key',
    title: 'Twilio account SID or API key',
    provider: 'Twilio',
    pattern: /\b((?:AC|SK)[a-f0-9]{32})\b/g,
    severity: 'high',
    revocation: 'Rotate credentials in the Twilio console.',
  },
  {
    id: 'supabase-service-role-key',
    title: 'Supabase service role key',
    provider: 'Supabase',
    pattern: /\b(sbp_[A-Za-z0-9]{40,})\b/g,
    severity: 'critical',
    revocation: 'Rotate the service role key in Supabase project settings.',
  },
  {
    id: 'database-connection-string',
    title: 'Database connection string with embedded password',
    provider: 'Database',
    pattern:
      /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql):\/\/[^:\s"'`]+:[^@\s"'`]{3,}@[^\s"'`/]+)/g,
    severity: 'critical',
    revocation: 'Rotate the database user password and update the deployment secret.',
  },
  {
    id: 'azure-storage-key',
    title: 'Azure storage account key',
    provider: 'Azure',
    pattern: /AccountKey=([A-Za-z0-9+/=]{60,})/g,
    severity: 'critical',
    revocation: 'Regenerate the storage account key in the Azure portal.',
  },
  {
    id: 'hugging-face-token',
    title: 'Hugging Face access token',
    provider: 'Hugging Face',
    pattern: /\b(hf_[A-Za-z0-9]{30,})\b/g,
    severity: 'high',
    revocation: 'Revoke at huggingface.co/settings/tokens.',
  },
  {
    id: 'openrouter-api-key',
    title: 'OpenRouter API key',
    provider: 'OpenRouter',
    pattern: /\b(sk-or-v1-[a-f0-9]{48,})\b/g,
    severity: 'critical',
    revocation: 'Revoke at openrouter.ai/keys.',
  },
  {
    id: 'clerk-secret-key',
    title: 'Clerk secret key',
    provider: 'Clerk',
    pattern: /\b(sk_(?:test|live)_[A-Za-z0-9]{30,})\b/g,
    severity: 'critical',
    revocation: 'Rotate the secret key in the Clerk dashboard.',
  },
];

/**
 * Variable names that make a high-entropy string worth flagging even without a
 * recognizable provider prefix.
 */
export const GENERIC_SECRET_ASSIGNMENT =
  /\b((?:api[_-]?key|apikey|secret|password|passwd|pwd|token|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key|encryption[_-]?key|credential)s?)\s*[:=]\s*["'`]([^"'`\s]{12,120})["'`]/gi;

/** Shannon entropy in bits per character. Random base64 sits around 4.5-6. */
export function shannonEntropy(value: string): number {
  if (!value.length) return 0;
  const frequencies = new Map<string, number>();
  for (const char of value) frequencies.set(char, (frequencies.get(char) ?? 0) + 1);

  let entropy = 0;
  for (const count of frequencies.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

/**
 * Values that look like secrets but are not.
 *
 * This list is the difference between a scanner people use and one they mute.
 * Every entry here was chosen because it appears in real repositories as
 * documentation, test data, or a template placeholder.
 */
const PLACEHOLDER_PATTERNS: RegExp[] = [
  /^(?:x{3,}|y{3,}|z{3,}|a{3,}|0{3,}|1{3,}|\.{3,}|\*{3,})$/i,
  /(?:your|my|the|insert|replace|example|sample|dummy|fake|test|placeholder|changeme|todo|xxx|abc123|foobar|redacted|removed|hidden|none|null|undefined|empty)/i,
  /^(?:true|false|null|undefined|localhost|127\.0\.0\.1)$/i,
  /^\$\{[^}]*\}$/,
  /^\{\{[^}]*\}\}$/,
  /^%[A-Za-z_]+%$/,
  /^<[^>]+>$/,
  /^process\.env\./,
  /^os\.environ/,
  /^\$[A-Z_]+$/,
  /^@[a-z]/i,
  // Common non-secret shapes: file paths, URLs without credentials, mime types.
  /^(?:\.{0,2}\/|https?:\/\/(?!\S*:\S*@))/,
  /^[a-z]+\/[a-z+.-]+$/i,
  // Repeated single character, or a simple ascending sequence.
  /^(.)\1{5,}$/,
];

/** Hex strings that are almost certainly hashes/ids rather than live secrets. */
const HASH_LIKE = /^[a-f0-9]{32,64}$/i;

export function isLikelyPlaceholder(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < 8) return true;
  return PLACEHOLDER_PATTERNS.some((pattern) => pattern.test(trimmed));
}

export interface SecretAssessment {
  isSecret: boolean;
  entropy: number;
  confidence: 'low' | 'medium' | 'high';
  reason: string;
}

/**
 * Decide whether a high-entropy string assigned to a suspicious variable is
 * worth reporting. Errs toward *not* reporting: a wrong secret finding costs
 * the developer real time chasing a value that was never live.
 */
export function assessGenericSecret(
  variableName: string,
  value: string,
  filePath: string,
): SecretAssessment {
  const entropy = shannonEntropy(value);

  if (isLikelyPlaceholder(value)) {
    return {
      isSecret: false,
      entropy,
      confidence: 'low',
      reason: 'Value looks like a placeholder',
    };
  }

  // `.env.example` and friends exist precisely to hold fake values.
  if (/\.(?:example|sample|template|dist)$|(?:example|sample|template)\.[a-z]+$/i.test(filePath)) {
    return { isSecret: false, entropy, confidence: 'low', reason: 'Example/template file' };
  }

  if (HASH_LIKE.test(value) && !/secret|password|token|key/i.test(variableName)) {
    return {
      isSecret: false,
      entropy,
      confidence: 'low',
      reason: 'Looks like a hash or identifier',
    };
  }

  // A long value made only of lowercase letters is prose, not a credential.
  if (/^[a-z\s]+$/.test(value)) {
    return { isSecret: false, entropy, confidence: 'low', reason: 'Value is plain lowercase text' };
  }

  if (entropy < 3.0) {
    return {
      isSecret: false,
      entropy,
      confidence: 'low',
      reason: 'Entropy too low to be a real key',
    };
  }

  const inTestPath = /(?:^|\/)(?:tests?|spec|__tests__|fixtures?|mocks?)(?:\/|$)/i.test(filePath);
  const strongName = /secret|password|private[_-]?key|api[_-]?key|token|credential/i.test(
    variableName,
  );

  if (entropy >= 4.2 && strongName && !inTestPath) {
    return {
      isSecret: true,
      entropy,
      confidence: 'high',
      reason: 'High entropy value in a credential field',
    };
  }
  if (entropy >= 3.5 && strongName) {
    return {
      isSecret: true,
      entropy,
      confidence: inTestPath ? 'low' : 'medium',
      reason: 'Moderate entropy value in a credential field',
    };
  }

  return {
    isSecret: false,
    entropy,
    confidence: 'low',
    reason: 'Does not meet the entropy threshold',
  };
}

/** Show enough to identify the credential, never enough to use it. */
export function maskSecret(secret: string): string {
  if (secret.length <= 8) return '*'.repeat(secret.length);
  return `${secret.slice(0, 4)}${'*'.repeat(Math.min(20, secret.length - 8))}${secret.slice(-4)}`;
}
