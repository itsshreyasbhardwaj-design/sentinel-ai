## What this changes

<!-- What does this do, and why is it needed? -->

## Why this approach

<!--
If you made a trade-off, chose between alternatives, or did something
non-obvious, say so here. This is the part reviewers cannot reconstruct from
the diff.
-->

## Type of change

- [ ] Bug fix
- [ ] New detection rule
- [ ] New scanner integration
- [ ] Feature
- [ ] Refactor (no behaviour change)
- [ ] Documentation
- [ ] Breaking change

## Testing

<!-- How did you verify this? Name the tests you added. -->

- [ ] `pnpm verify` passes
- [ ] `pnpm test:e2e` passes (if the app or API changed)
- [ ] New tests cover the change

### For a new detection rule

- [ ] Fixture added to `fixtures/`
- [ ] Test asserts the rule fires on the fixture
- [ ] CWE and, where applicable, OWASP taxonomy attached
- [ ] Knowledge-base topic exists so the finding gets a real explanation
- [ ] Checked against a realistic codebase for false positives

## Security considerations

<!--
Does this touch untrusted input, subprocess execution, file paths, or anything
that reaches a report? If so, what threat did you consider?
-->

- [ ] No new absolute host paths reach findings
- [ ] No secrets can reach logs, reports or exports
- [ ] Untrusted input is validated at the boundary
