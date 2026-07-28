import { describe, expect, it } from 'vitest';
import {
  compareVersionStrings,
  lowestFixedVersion,
  osvRangeToExpression,
  parseVersion,
  satisfiesRange,
} from './semver.js';

describe('parseVersion', () => {
  it('parses full and partial versions', () => {
    expect(parseVersion('1.2.3')).toMatchObject({ major: 1, minor: 2, patch: 3 });
    expect(parseVersion('v2.0')).toMatchObject({ major: 2, minor: 0, patch: 0 });
    expect(parseVersion('=3')).toMatchObject({ major: 3, minor: 0, patch: 0 });
  });

  it('parses pre-release identifiers', () => {
    expect(parseVersion('1.0.0-beta.2')?.prerelease).toEqual(['beta', 2]);
  });

  it('returns undefined for non-versions', () => {
    expect(parseVersion('unknown')).toBeUndefined();
    expect(parseVersion('')).toBeUndefined();
  });
});

describe('compareVersionStrings', () => {
  it('orders numerically, not lexically', () => {
    expect(compareVersionStrings('1.10.0', '1.9.0')).toBeGreaterThan(0);
    expect(compareVersionStrings('2.0.0', '10.0.0')).toBeLessThan(0);
  });

  it('sorts a pre-release before its release', () => {
    expect(compareVersionStrings('1.0.0-beta', '1.0.0')).toBeLessThan(0);
    expect(compareVersionStrings('1.0.0-alpha', '1.0.0-beta')).toBeLessThan(0);
  });
});

describe('satisfiesRange', () => {
  it('handles simple upper bounds', () => {
    expect(satisfiesRange('4.17.15', '<4.17.21')).toBe(true);
    expect(satisfiesRange('4.17.21', '<4.17.21')).toBe(false);
    expect(satisfiesRange('5.0.0', '<4.17.21')).toBe(false);
  });

  it('ANDs space-separated clauses', () => {
    expect(satisfiesRange('4.5.0', '>=4.0.0 <5.0.0')).toBe(true);
    expect(satisfiesRange('3.9.0', '>=4.0.0 <5.0.0')).toBe(false);
    expect(satisfiesRange('5.0.0', '>=4.0.0 <5.0.0')).toBe(false);
  });

  it('ORs groups separated by ||', () => {
    const range = '<5.7.2 || >=6.0.0 <6.3.1 || >=7.0.0 <7.5.2';
    expect(satisfiesRange('5.7.1', range)).toBe(true);
    expect(satisfiesRange('6.3.0', range)).toBe(true);
    expect(satisfiesRange('7.5.1', range)).toBe(true);
    expect(satisfiesRange('7.5.2', range)).toBe(false);
    expect(satisfiesRange('6.3.1', range)).toBe(false);
  });

  it('is false rather than throwing for an unparseable version', () => {
    expect(satisfiesRange('unknown', '<1.0.0')).toBe(false);
  });

  it('matches the real lodash advisory range', () => {
    expect(satisfiesRange('4.17.15', '<4.17.21')).toBe(true);
    expect(satisfiesRange('4.17.21', '<4.17.21')).toBe(false);
  });
});

describe('osvRangeToExpression', () => {
  it('converts introduced/fixed pairs', () => {
    const expression = osvRangeToExpression([{ introduced: '1.0.0' }, { fixed: '1.2.3' }]);
    expect(expression).toBe('>=1.0.0 <1.2.3');
    expect(satisfiesRange('1.1.0', expression)).toBe(true);
    expect(satisfiesRange('1.2.3', expression)).toBe(false);
  });

  it('treats introduced 0 as everything from the beginning', () => {
    const expression = osvRangeToExpression([{ introduced: '0' }, { fixed: '2.0.0' }]);
    expect(satisfiesRange('0.1.0', expression)).toBe(true);
  });

  it('handles last_affected', () => {
    const expression = osvRangeToExpression([{ introduced: '1.0.0' }, { last_affected: '1.5.0' }]);
    expect(satisfiesRange('1.5.0', expression)).toBe(true);
    expect(satisfiesRange('1.5.1', expression)).toBe(false);
  });

  it('leaves an unfixed range open-ended', () => {
    const expression = osvRangeToExpression([{ introduced: '3.0.0' }]);
    expect(satisfiesRange('99.0.0', expression)).toBe(true);
  });

  it('joins multiple ranges with ||', () => {
    const expression = osvRangeToExpression([
      { introduced: '1.0.0' },
      { fixed: '1.5.0' },
      { introduced: '2.0.0' },
      { fixed: '2.3.0' },
    ]);
    expect(satisfiesRange('1.2.0', expression)).toBe(true);
    expect(satisfiesRange('1.6.0', expression)).toBe(false);
    expect(satisfiesRange('2.1.0', expression)).toBe(true);
  });
});

describe('lowestFixedVersion', () => {
  it('returns the earliest fix', () => {
    expect(lowestFixedVersion(['7.5.2', '5.7.2', '6.3.1'])).toBe('5.7.2');
  });

  it('returns undefined when there is no fix', () => {
    expect(lowestFixedVersion([])).toBeUndefined();
  });
});
