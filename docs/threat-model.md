# Threat model

## Assets

- Source code and configuration being scanned
- Credentials accidentally present in those files
- Integrity of findings, severities, fingerprints, and exit codes
- Integrity and confidentiality of local report-signing keys
- Availability of developer workstations and CI runners

## Trust boundaries

The target is fully untrusted. File names, directory depth, source text, JSON, and AST shape can all be adversarial. Baseline, current, and signed-envelope files are untrusted as well. In GitHub Actions, checked-out source and workflow inputs are untrusted scanner data; the runner-provided environment and command-file paths are trusted. The local process, its installed lockfile, and the public-key distribution channel chosen by the user are trusted. No network service is part of the current product.

## Controls

- Resolve the requested target to a canonical root once.
- Never follow discovered symlinks.
- Ignore dependency, VCS, build, coverage, and vendor directories.
- Enforce maximum file size and total file count.
- Bound retained decoded input and lockfile bytes to 100 MB and count every encountered candidate file, including unsupported or skipped candidates, against the 10,000-file budget.
- Bound source-location and full-line sanitization work to 64 evidence snippets per file; exceeding the budget fails the affected rule closed.
- Retain at most 5,000 raw findings before deduplication; stop rule iteration and fail the scan as incomplete when a rule attempts to exceed that bound.
- Bound one-hop JavaScript and TypeScript analysis to 1,000 unique imported call states; exceeding the budget produces an error diagnostic instead of a partial clean result.
- Decode text as strict UTF-8 and skip other encodings.
- Detect canonical Git LFS pointers in supported inputs and absent or empty declared submodules without invoking `git` or fetching content.
- Treat discovered symlinks, unresolved LFS inputs, unmaterialized submodules, skipped scannable inputs, exhausted resource budgets, and zero-file targets as incomplete scans with error diagnostics.
- Parse source as data; never import it or invoke package scripts.
- Give every rule an independent failure boundary and surface rule failures as scan errors.
- Redact recognized credential ranges on the full source line before evidence truncation, then apply format-wide redaction before fingerprinting or writing reports.
- Redact source-derived paths, metadata, finding messages, and diagnostics; consume complete private-key blocks with a forward-only parser; and escape terminal and bidirectional controls before output.
- Center bounded evidence on the reported offset only after sanitizing the complete source line.
- Write report files through a same-directory temporary file and atomic rename with mode `0600` where POSIX modes are supported.
- Use relative artifact paths in every output format.
- Accept repository provenance only as an explicit URL/commit pair; require HTTPS and reject URL credentials, queries, and fragments.
- Bound comparison reports to 10 MB, require strict UTF-8, and validate the fields used before comparison.
- Normalize and redact reports before signing; bind the exact payload bytes to a versioned Ed25519 signature.
- Require an explicitly supplied public key for verification and match its complete SPKI SHA-256 fingerprint.
- Bound signed payloads to 10 MB, require canonical base64url, and reject unknown envelope fields.
- Generate private keys with owner-only permissions, refuse to overwrite key files, and reject broadly readable private keys on POSIX systems.
- Resolve Action targets through their real path and reject anything outside `GITHUB_WORKSPACE`.
- Resolve the nearest existing Action output ancestor and reject directory links that escape the workspace before creating any missing descendant; also reject absolute paths, parent traversal, overlapping output topology, NFC/lowercase aliases, Windows device and alternate-data-stream names, target overwrite, and pre-existing in-target outputs.
- Bundle the Action's production dependency, regenerate it byte-for-byte in CI, and run it on Node 24 without install or network steps.
- Keep source-derived findings out of workflow logs; write only trusted numeric counts to the step summary.
- Publish the step summary before successful outputs so a later summary failure cannot leave a stale `passed` outcome.
- Preserve incomplete-scan diagnostics in SARIF execution notifications and mark the invocation unsuccessful on diagnostic errors.

## Known limitations

- Uleravo assumes the workspace remains stable for the duration of discovery and report writing. Opened regular files are identity-checked and read under the configured byte limits, but Node's path APIs do not provide an atomic recursive directory snapshot or an atomic plan-and-write operation across output ancestors. Scan an immutable checkout and do not concurrently rename target or output directories or replace them with links.
- Conventional `build`, `dist`, and `out` directories are ignored during a repository-root scan to avoid duplicate generated code. If generated output is the only runtime artifact or can differ materially from source, scan that directory explicitly as the target.
- Uleravo recognizes canonical Git LFS pointer records and declared submodule directories, but it does not prove that a materialized LFS object or submodule matches an expected remote object ID or commit. Scan an immutable, fully materialized checkout and rely on the checkout boundary for that identity.
- JavaScript and TypeScript taint tracking is primarily intraprocedural and intentionally narrow. It follows transparent type assertions, non-null assertions, `satisfies` expressions, and one direct call from a recognized handler to a top-level exported function reached through a static named relative ESM import. It does not follow default, namespace, CommonJS, dynamic, or package imports; re-exports; TypeScript path aliases; return flow; arbitrary helper graphs; or second-hop calls, and it can miss complex control flow.
- Filesystem and SSRF findings have medium confidence because a guard may live outside the visible expression.
- Python handler tracking is intraprocedural and intentionally narrow. It binds standard decorators to FastMCP or Server instances resolved from top-level imports, resolves direct import aliases and common HTTP clients, and propagates parameters through local assignments. It can miss local imports, custom factories or wrappers, interprocedural flow, dynamic registration, and exotic syntax outside its logical-statement model.
- YAML, TOML, and environment files receive credential and URL checks, not language-aware data-flow analysis.
- Credential heuristics favor precision. Generic candidates containing synthetic markers such as `fake`, `test`, `example`, `placeholder`, or `redacted` are suppressed by a broad placeholder heuristic. Known provider-secret shapes remain reportable in recognized test and example paths unless they match an exact documented provider example or their body is unmistakable repeated or sequential fixture filler. Generic source matches require quoted literals; unquoted matches are limited to environment, YAML, and TOML assignments. Public `phc_` ingest keys are ignored without excluding those files wholesale.
- JavaScript and TypeScript handler/tool-metadata analysis, Python handler analysis, and cleartext-transport checks skip recognized test files according to their rule-specific boundaries, including common hyphenated or underscored test paths and filenames; credential rules continue scanning them. XML namespace URIs, JSON Schema draft-04/draft-07 meta-schema identifiers, the Apache license identifier, and the conventional `http://proxy` help placeholder are not treated as outbound endpoints.
- A URL whose authority contains a format placeholder is not treated as a literal remote transport. JavaScript/TypeScript and Python handler data-flow rules still report tool-controlled destinations when the flow is locally visible.
- Python outbound-request tracking treats a directly formatted URL as fixed-destination only when its literal prefix contains the complete HTTP(S) authority and reaches a path, query, or fragment delimiter. It can still miss equivalent fixed-origin construction through assignments or helpers.
- Static analysis cannot validate runtime authorization, consent prompts, OAuth scopes, TLS configuration, DNS rebinding defenses, sandboxing, or tool behavior that differs from source.
- Redaction recognizes supported credential shapes and URL locations. Reports should still be handled as sensitive security artifacts.
- A valid signature proves control of the corresponding private key, not the signer's real-world identity, the correctness of the scanner, or that the provenance claim matches the source that was scanned.
- Uleravo does not provide key escrow, rotation, revocation, or a public-key directory. The user must protect the private key and distribute the public key through a trusted channel.

## Hosted-phase requirements

Before a hosted service accepts customer data, it must add authenticated encryption for report objects, explicit retention, tenant-isolation tests, upload size and content limits, rate limits, audit events, deletion verification, and a documented incident path. A hosted worker must never execute an uploaded package.
