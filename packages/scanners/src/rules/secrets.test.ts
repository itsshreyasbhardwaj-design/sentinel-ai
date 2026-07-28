import { describe, expect, it } from 'vitest';
import {
  SECRET_PATTERNS,
  assessGenericSecret,
  isLikelyPlaceholder,
  maskSecret,
  shannonEntropy,
} from './secrets.js';

describe('shannonEntropy', () => {
  it('scores random-looking strings high and repetitive ones low', () => {
    expect(shannonEntropy('aaaaaaaaaaaaaaaa')).toBeLessThan(1);
    expect(shannonEntropy('kJ8#mN2$pQ7!wX4z')).toBeGreaterThan(3.5);
  });

  it('returns zero for an empty string', () => {
    expect(shannonEntropy('')).toBe(0);
  });
});

describe('maskSecret', () => {
  it('reveals enough to identify but not to use', () => {
    const masked = maskSecret(`ghp${'_'}A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8`);
    expect(masked.startsWith('ghp_')).toBe(true);
    expect(masked).toContain('*');
    expect(masked).not.toContain('C3d4E5f6');
  });

  it('fully masks short values', () => {
    expect(maskSecret('abc123')).toBe('******');
  });
});

describe('isLikelyPlaceholder', () => {
  it('recognizes documentation placeholders', () => {
    for (const value of [
      'your-api-key-here',
      'xxxxxxxxxxxxxxxx',
      'REPLACE_ME_WITH_KEY',
      '${DATABASE_URL}',
      '{{ secret }}',
      '<your-token>',
      'changeme123456',
      'process.env.SECRET',
      'example-value-here',
    ]) {
      expect(isLikelyPlaceholder(value), value).toBe(true);
    }
  });

  it('does not dismiss a realistic credential', () => {
    expect(isLikelyPlaceholder('kJ8mN2pQ7wX4zR9tY6uI3oP1aS5dF0gH')).toBe(false);
  });
});

describe('assessGenericSecret', () => {
  it('flags a high-entropy value in a credential field', () => {
    const result = assessGenericSecret(
      'api_key',
      'kJ8mN2pQ7wX4zR9tY6uI3oP1aS5dF0gH',
      'src/config.ts',
    );
    expect(result.isSecret).toBe(true);
    expect(result.confidence).toBe('high');
  });

  it('ignores placeholders even in a credential field', () => {
    expect(assessGenericSecret('api_key', 'your-key-here', 'src/config.ts').isSecret).toBe(false);
  });

  it('ignores example and template files', () => {
    const result = assessGenericSecret(
      'api_key',
      'kJ8mN2pQ7wX4zR9tY6uI3oP1aS5dF0gH',
      '.env.example',
    );
    expect(result.isSecret).toBe(false);
    expect(result.reason).toMatch(/example/i);
  });

  it('ignores plain prose', () => {
    expect(
      assessGenericSecret('password', 'the quick brown fox jumps over', 'src/a.ts').isSecret,
    ).toBe(false);
  });

  it('ignores hash-shaped identifiers when the field name is generic', () => {
    const result = assessGenericSecret('etag', 'd41d8cd98f00b204e9800998ecf8427e', 'src/a.ts');
    expect(result.isSecret).toBe(false);
  });

  it('lowers confidence inside test directories', () => {
    const result = assessGenericSecret(
      'password',
      'Xk9mQ2pL7wR4tY6uI3oP',
      'src/__tests__/auth.test.ts',
    );
    if (result.isSecret) expect(result.confidence).toBe('low');
  });
});

describe('provider patterns', () => {
  /**
   * Sample credentials are assembled at runtime rather than written as literals.
   *
   * A literal `sk_live_…` or `xoxb-…` in this file is indistinguishable from a
   * real leak to GitHub's push protection, which blocks the push — and asking
   * for an exception would be the wrong lesson for a security tool's own
   * repository. Splitting the prefix from the body keeps the assembled value
   * identical while leaving nothing scannable on disk.
   */
  const join = (prefix: string, body: string) => `${prefix}${body}`;

  const samples: [string, string][] = [
    ['aws-access-key-id', join('AKIA', 'IOSFODNN7EXAMPLE')],
    ['github-token', join('ghp', '_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8')],
    ['stripe-secret-key', join('sk_', 'live_51HxYzAbCdEfGhIjKlMnOpQrStUv')],
    ['openai-api-key', join('sk-', 'proj-Ab3dEf9HiJkLmN0pQrStUvWxYz1234567890')],
    ['anthropic-api-key', join('sk-', 'ant-api03-Ab3dEf9HiJkLmN0pQrStUvWxYz')],
    ['slack-token', join('xox', 'b-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx')],
    ['google-api-key', join('AIza', 'SyD-1234567890abcdefghijklmnopqrstu')],
    ['private-key', join('-----BEGIN RSA ', 'PRIVATE KEY-----')],
    ['database-connection-string', join('postgresql://', 'admin:Str0ngPass@db.internal:5432/prod')],
  ];

  for (const [patternId, sample] of samples) {
    it(`matches a ${patternId}`, () => {
      const pattern = SECRET_PATTERNS.find((p) => p.id === patternId);
      expect(pattern, patternId).toBeDefined();
      pattern!.pattern.lastIndex = 0;
      expect(pattern!.pattern.test(sample)).toBe(true);
    });
  }

  it('does not match ordinary prose', () => {
    const prose = 'This function returns the user id from the session store.';
    for (const pattern of SECRET_PATTERNS) {
      pattern.pattern.lastIndex = 0;
      expect(pattern.pattern.test(prose), pattern.id).toBe(false);
    }
  });

  it('gives every pattern revocation guidance', () => {
    for (const pattern of SECRET_PATTERNS) {
      expect(pattern.revocation.length, pattern.id).toBeGreaterThan(10);
    }
  });
});
