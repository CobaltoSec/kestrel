## Summary

<!-- One paragraph: what this PR does and why. -->

## Type

- [ ] feat — new capability
- [ ] fix — bug fix
- [ ] docs — documentation only
- [ ] refactor — no behavior change
- [ ] test — tests only

## Scope

- [ ] fingerprint category
- [ ] phase change (`p<N>-*.md`)
- [ ] platform integration
- [ ] state schema
- [ ] scripts

## Checklist

- [ ] `pytest tests/test_fingerprint.py` passes (if fingerprint touched)
- [ ] No hardcoded tokens, passwords, or real IPs outside `10.x.x.x` lab ranges
- [ ] HITL count unchanged, or change justified below
- [ ] State schema change is additive, or migration path documented
- [ ] Platform TOS verified (retired-only WebSearch, no active machine writeups)
- [ ] Commit messages follow `<type>(<scope>): <subject>` convention

## HITL justification (if gate added or removed)

<!-- Target is ≤6 total gates. -->

## Testing evidence

<!-- Paste test run output or a short session log. Redact tokens and credentials. -->
