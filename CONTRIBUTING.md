# Contributing

Keep changes narrow and evidence-driven.

1. Add a vulnerable fixture that demonstrates the risk.
2. Add a guarded fixture that must stay clean.
3. Implement the smallest AST or structured-data rule that separates them.
4. Give the finding a confidence level, remediation, and only defensible standards mappings.
5. Run `pnpm check` and `pnpm scan:self`.

Rules must not execute target code, make network requests, follow symlinks, include absolute paths in reports, or serialize credential values. A new dependency needs a concrete reason in the pull request and must be exact-pinned.

Changes that affect the scanner or GitHub adapter must regenerate and verify the committed Action bundle:

```bash
pnpm build:action
pnpm check:action
```
Unless explicitly designated otherwise in writing, contributions submitted for inclusion in the public scanner core are licensed under the Apache License 2.0.
