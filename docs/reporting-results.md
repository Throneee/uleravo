# Reporting results and corrections

Uleravo's reports are redacted, but they are not automatically safe to publish. A report can still reveal private filenames, package names, repository identity, commit identifiers, tool names, internal architecture, source fragments, endpoint hostnames, finding messages, and hashes derived from the scanned tree.

Use a public issue only when the entire report can be explained with a small synthetic reproducer. Use the private security contact published for the release when the concern involves a scanner vulnerability, a redaction failure, a real exploitable condition, embargoed research, or anything that cannot be reproduced without sensitive material.

## Never publish these materials

- Private or proprietary source code
- Credentials, tokens, passwords, cookies, private keys, connection strings, or secret values, including revoked values
- A complete JSON or SARIF report from a private repository
- Raw finding evidence copied from a private target
- Private repository URLs, commit identifiers, internal package names, customer names, tenant identifiers, or non-public hostnames
- Lockfiles, scan-input hashes, private artifacts, workflow logs, or screenshots that contain any of the above

Do not rely on `<redacted>` markers alone. Review every field and every surrounding line before sharing it. If a finding reveals a real credential in the original source, rotate it and handle the repository history as an exposure even when Uleravo redacted the report.

## Choose the report type

**False positive:** Uleravo emitted a finding, but a visible guard or supported context makes the stated risk inapplicable.

**Detection gap:** A synthetic vulnerable example is within the documented rule boundary but produces no finding. Report a real unpatched vulnerability privately first; do not publish working exploit details to demonstrate the gap.

**Rule correction:** The title, severity, confidence, remediation, standards mapping, location, or evidence boundary is inaccurate or unclear.

**Incomplete-scan problem:** An error diagnostic is wrong, missing, unsafe, or does not explain how to make the scan complete. An incomplete scan must never be presented as a clean result.

## Create a safe reproducer

1. Copy only the smallest syntax needed to reproduce the behavior into a new temporary file.
2. Replace filenames with neutral paths such as `src/example.ts` or `server.py`.
3. Replace organization, repository, package, tool, function, and variable names with generic names.
4. Replace domains with reserved documentation domains such as `example.com` and use loopback addresses only when locality is part of the test.
5. Replace every credential with an unmistakably synthetic placeholder. Never preserve a real credential's prefix, suffix, length, or structure merely to make the detector match.
6. Remove comments, metadata, unrelated imports, and surrounding business logic.
7. Run the same Uleravo version against the synthetic directory and confirm that it still demonstrates the issue.
8. Inspect the final text as if it were public forever. When uncertain, use the private reporting route.

Do not mutate private source in place to prepare a report. Work from a separate synthetic file so an accidental commit or attachment cannot expose the original.

## Public correction template

Copy this template into a public issue only after completing the sanitization steps. Omit any field that cannot be made safely public.

````markdown
## Classification

- Type: false positive | detection gap | rule correction | incomplete-scan problem
- Rule ID: MCP___
- Uleravo version: 0.6.3
- Installation: GitHub Action | local development build
- Action commit SHA, if applicable: <public Uleravo Action commit>
- Language or file type: JavaScript | TypeScript | Python | JSON | YAML | TOML | other

## Expected behavior

Describe the expected finding or non-finding and why, using only synthetic names.

## Actual behavior

Describe what Uleravo returned. Include only sanitized values such as the rule ID,
severity, confidence, and diagnostic type. Do not paste a complete report.

## Minimal synthetic reproducer

```text
Place the smallest synthetic example here.
Do not include private source, real endpoints, credentials, or internal names.
```

## Security reasoning

For a false positive, identify the exact visible guard and the invariant it enforces.
For a detection gap, explain which documented rule boundary should recognize the
synthetic pattern. Do not include exploit steps for a real unpatched system.

## Reproduction

1. Save the synthetic example as `<neutral path>`.
2. Scan only the synthetic directory with the version above.
3. State the observed rule IDs and whether the scan was complete.

## Suggested correction

Optional: describe a narrow rule, message, remediation, or documentation change.
````

## Safe fields and fields to omit

The following values are usually sufficient after manual review:

- Public Uleravo version and Action commit
- Rule ID, default severity, and confidence
- Whether the scan was complete
- Sanitized diagnostic type and a paraphrase of its message
- Operating-system family when the behavior is platform-specific
- A minimal synthetic reproducer

Do not attach the original `uleravo.json` or `uleravo.sarif`. In particular, omit or replace `evidence`, `file`, `provenance.repository`, `provenance.package`, `scanInputSha256`, lockfile paths and hashes, fingerprints, private scan IDs, and source-derived finding messages. A fingerprint is stable for comparison, not a safe or necessary public identifier.

## Triage expectations

Maintainers may ask for a smaller synthetic fixture, the exact public scanner commit, or clarification of the security invariant. They should never need a real credential or a complete private report to reproduce a correction. A confirmed correction should become a vulnerable/guarded fixture pair where applicable, followed by the narrowest analyzer or documentation change that separates the cases.

Uleravo v0.6.x intentionally has no inline suppression format. While a result is under review, keep the original evidence private and record the temporary risk decision in the repository's existing review process. Avoid broad `exclude` entries that could hide unrelated findings or make the selected target incomplete.
