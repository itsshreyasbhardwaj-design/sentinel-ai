import { describe, expect, it } from 'vitest';
import { dedupeFindings, filterFindings, normalizeFindings, sortFindings } from './normalize.js';
import type { RawFinding } from './types.js';

const base: RawFinding = {
  ruleId: 'sql-injection',
  title: 'SQL injection',
  severity: 'critical',
  kind: 'sast',
  location: {
    path: './src/db.ts',
    startLine: 12,
    snippet: 'query("SELECT * FROM u WHERE id=" + id)',
  },
};

const ctx = { scanId: 'scan_1', scanner: 'native-sast', scannerKind: 'native' as const };

describe('normalizeFindings', () => {
  it('assigns stable identity and normalizes paths', () => {
    const [finding] = normalizeFindings([base], ctx);
    expect(finding?.location?.path).toBe('src/db.ts');
    expect(finding?.fingerprint).toHaveLength(32);
    expect(finding?.id.startsWith('fnd_')).toBe(true);
    expect(finding?.status).toBe('open');
    expect(finding?.riskScore).toBeGreaterThan(0);
  });

  it('keeps the fingerprint stable when line numbers shift', () => {
    const [a] = normalizeFindings([base], ctx);
    const [b] = normalizeFindings(
      [{ ...base, location: { ...base.location!, startLine: 400 } }],
      ctx,
    );
    expect(a?.fingerprint).toBe(b?.fingerprint);
  });

  it('keeps the fingerprint stable across whitespace reformatting', () => {
    const [a] = normalizeFindings([base], ctx);
    const [b] = normalizeFindings(
      [
        {
          ...base,
          location: { ...base.location!, snippet: '  QUERY("select * from u where id=" + id)  ' },
        },
      ],
      ctx,
    );
    // Case and whitespace are normalized away before hashing.
    expect(a?.fingerprint).toBe(b?.fingerprint);
  });

  it('changes the fingerprint when the rule or file changes', () => {
    const [a] = normalizeFindings([base], ctx);
    const [b] = normalizeFindings([{ ...base, ruleId: 'xss' }], ctx);
    const [c] = normalizeFindings(
      [{ ...base, location: { ...base.location!, path: 'src/other.ts' } }],
      ctx,
    );
    expect(a?.fingerprint).not.toBe(b?.fingerprint);
    expect(a?.fingerprint).not.toBe(c?.fingerprint);
  });

  it('truncates oversized snippets', () => {
    const [finding] = normalizeFindings(
      [{ ...base, location: { ...base.location!, snippet: 'x'.repeat(5000) } }],
      ctx,
    );
    expect(finding?.location?.snippet?.length).toBeLessThanOrEqual(401);
  });

  it('applies matching suppressions', () => {
    const [finding] = normalizeFindings([base], {
      ...ctx,
      suppressions: [{ path: 'src/*', ruleId: 'sql-injection', reason: 'legacy module' }],
    });
    expect(finding?.suppressed).toBe(true);
    expect(finding?.status).toBe('accepted-risk');
    expect(finding?.suppressionReason).toBe('legacy module');
  });

  it('ignores expired suppressions', () => {
    const [finding] = normalizeFindings([base], {
      ...ctx,
      suppressions: [
        { ruleId: 'sql-injection', reason: 'temporary', expiresAt: '2020-01-01T00:00:00Z' },
      ],
    });
    expect(finding?.suppressed).toBeUndefined();
  });

  it('preserves firstSeenAt for previously seen fingerprints', () => {
    const [first] = normalizeFindings([base], ctx);
    const [second] = normalizeFindings([base], {
      ...ctx,
      previouslySeen: new Map([[first!.fingerprint, '2020-05-05T00:00:00.000Z']]),
    });
    expect(second?.firstSeenAt).toBe('2020-05-05T00:00:00.000Z');
  });
});

describe('dedupeFindings', () => {
  it('collapses the same issue reported by two scanners and raises confidence', () => {
    const native = normalizeFindings([{ ...base, confidence: 'medium' }], ctx);
    const external = normalizeFindings([{ ...base, confidence: 'low' }], {
      ...ctx,
      scanner: 'semgrep',
      scannerKind: 'external',
    });

    const deduped = dedupeFindings([...native, ...external]);
    expect(deduped).toHaveLength(1);
    expect(deduped[0]?.confidence).toBe('high');
    expect(deduped[0]?.metadata?.corroboratedBy).toContain('semgrep');
  });

  it('keeps the higher-severity copy', () => {
    const low = normalizeFindings([{ ...base, severity: 'low' }], ctx);
    const critical = normalizeFindings([base], { ...ctx, scanner: 'other' });
    const deduped = dedupeFindings([...low, ...critical]);
    expect(deduped[0]?.severity).toBe('critical');
  });

  it('leaves genuinely distinct findings alone', () => {
    const findings = normalizeFindings([base, { ...base, ruleId: 'xss' }], ctx);
    expect(dedupeFindings(findings)).toHaveLength(2);
  });
});

describe('sortFindings', () => {
  it('orders by risk score descending and is deterministic', () => {
    const findings = normalizeFindings(
      [
        { ...base, ruleId: 'low', severity: 'low' },
        { ...base, ruleId: 'crit', severity: 'critical' },
        { ...base, ruleId: 'med', severity: 'medium' },
      ],
      ctx,
    );
    const sorted = sortFindings(findings).map((f) => f.ruleId);
    expect(sorted).toEqual(['crit', 'med', 'low']);
    expect(sortFindings(findings).map((f) => f.ruleId)).toEqual(sorted);
  });
});

describe('filterFindings', () => {
  const findings = normalizeFindings(
    [
      { ...base, ruleId: 'sql', severity: 'critical', kind: 'sast' },
      {
        ...base,
        ruleId: 'dep',
        severity: 'medium',
        kind: 'dependencies',
        title: 'Vulnerable lodash',
      },
    ],
    ctx,
  );

  it('filters by severity and kind', () => {
    expect(filterFindings(findings, { severity: ['critical'] })).toHaveLength(1);
    expect(filterFindings(findings, { kind: ['dependencies'] })[0]?.ruleId).toBe('dep');
  });

  it('searches across title, rule and path', () => {
    expect(filterFindings(findings, { search: 'lodash' })).toHaveLength(1);
    expect(filterFindings(findings, { search: 'db.ts' })).toHaveLength(2);
    expect(filterFindings(findings, { search: 'nothing-here' })).toHaveLength(0);
  });

  it('returns everything when no filter is supplied', () => {
    expect(filterFindings(findings, {})).toHaveLength(2);
  });
});
