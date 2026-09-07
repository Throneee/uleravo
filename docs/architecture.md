# Architecture

## Current shape

Uleravo is one Node.js package with nine explicit boundaries:

1. **Discovery** resolves the target once, walks only regular files, enforces per-file, candidate-count, and aggregate-byte limits, detects unresolved LFS source and unmaterialized declared submodules, and returns normalized relative paths plus explicit incomplete-scan diagnostics.
2. **Rules** inspect immutable file records under per-file evidence-work and scanner-wide finding limits. JavaScript and TypeScript rules use the TypeScript AST and may build a bounded in-memory index over source files already admitted by discovery; Python handlers use a bounded lexer and logical-statement model; text and manifest rules use bounded deterministic parsing.
3. **Provenance** derives package metadata, lockfile hashes, and the normalized scan-input hash. Repository URL and commit are accepted only as an explicit pair and are never discovered by executing target tooling.
4. **Domain** creates redacted findings, stable fingerprints, summaries, and a versioned report envelope.
5. **Signatures** normalize and redact reports, bind their exact bytes to an Ed25519 signature, and verify them against an explicitly supplied public key.
6. **Artifact snapshots** capture bounded Skill or Codex Plugin raw-byte closures, declared identity, and explicit evidence states without executing components or contacting endpoints.
7. **Adapters** render text, JSON, or SARIF, compare reports as fingerprint multisets, and implement the CLI and workspace-confined GitHub Action.
8. **Harnesses** read bounded, explicitly supported local agent configuration as inert data, normalize declared capability and permission facts with source/applicability labels, and compare those facts without claiming unobserved runtime state.
9. **Capability graphs** bind one exact Skill content digest to one harness snapshot and classify only declared exposure. They resolve paths through stable, non-linked layer contexts, recapture inputs to detect changes, serialize no host paths or source bytes, and never assert runtime reachability or effect authority.

Rules do not perform I/O or load target modules. Formatters do not make security decisions. The scanner orchestrator catches each file-scoped or repository-scoped rule independently and records failures as diagnostics.

JavaScript and TypeScript repository analysis follows one supported edge: a direct call from a recognized handler to a top-level exported function reached through a static named relative ESM import. It is not a general module resolver or call graph. Ambiguous paths, re-exports, package imports, and further helper edges are deliberately left unresolved.

## Product boundary

The public Apache-2.0 core is useful without a hosted service. It consists of the local scanner, Skill and Codex Plugin artifact snapshots, the Codex local-configuration harness, exact-byte declared Skill correlation, CLI, MCP-focused GitHub Action, report schemas, offline verification, safe fixtures, and public documentation.

Private deterministic analysis stays in the user's checkout by default. The current Action does not upload source, contact a service, accept customer data, or create an account. Embargoed research, private corpus decisions, customer data, hosted monitoring, organization policy, service signing identity, team workflow, and billing are outside this repository and release surface.

Product expansion must preserve these boundaries through versioned adapters and domain contracts rather than coupling scanner rules to a hosted application.

## Completeness semantics

In v0.6.x, a complete scan means discovery and every selected rule completed without error diagnostics for the selected inputs. It does not mean that every vulnerability class, runtime condition, dependency, generated artifact, or deployment state was analyzed.

Artifact, harness, and correlation completeness are separate, explicit contracts. Each artifact-closure element and harness field records whether it is observed, declared, user-supplied, mutable, unresolved, endpoint-unverified, unsupported, or unavailable as applicable. The Codex harness snapshot also keeps effective runtime state explicitly unavailable. A complete capability graph supports only its declared-exposure classification; it does not make runtime discovery, initialization, authorization, or effect claims. A future advisory decision must not infer trust-decision completeness from the MCP `scan-complete` boolean, artifact `complete` flag, harness capture flag, or graph `complete` flag alone.

## Report contract

`schemaVersion` changes only for breaking report changes. Additive fields can ship within the same major schema. Finding fingerprints derive from rule ID, normalized relative path, and redacted normalized evidence; timestamps and line numbers do not make old findings appear new.

`provenance.scanInputSha256` covers the ordered relative paths and decoded contents admitted as scan inputs. If a later safety limit stops rule analysis, the digest can include inputs that were not fully rule-analyzed and the report is marked incomplete. Paths and contents use domain-separated, byte-length-prefixed framing so embedded text delimiters cannot create the same digest for different file sets. It is deliberately not described as a repository-tree hash. Lockfiles also carry raw-byte SHA-256 values, or an explicit `size-limit` state when the safety limit prevents hashing. The scan ID additionally binds every lockfile path, state, digest, and sanitized diagnostic because lockfile presence or incomplete analysis can change the meaning of otherwise identical admitted source.

Comparison pairs repeated fingerprints as a multiset, returns the current copy for unchanged findings, and sorts every result with the same finding order as a scan. It reads no clock or environment state, so identical report inputs produce byte-identical JSON comparison output.

Untrusted report parsing validates each stored fingerprint against the report's stored path and evidence before applying the current sanitizer. If stronger redaction changes either field, the returned normalized report receives the corresponding migrated fingerprint. This detects malformed findings and keeps older schema-1 reports readable; it does not make an untrusted pull-request baseline authoritative.

Signed-report envelopes contain the normalized report as canonical unpadded base64url, its SHA-256, the SHA-256 fingerprint of the signing public key's SPKI representation, and an Ed25519 signature over a versioned domain separator plus the exact payload bytes. The envelope has no signing timestamp or ambient identity, so signing the same report with the same key is deterministic. Verification requires the public key separately and rejects unknown envelope fields, non-canonical encodings, mismatched digests, wrong keys, invalid signatures, and non-normalized payloads.

The GitHub Action is a Node 24 adapter over the same library API. It converts GitHub's repository and commit environment into the scanner's explicit provenance input, confines targets and outputs to the real workspace, rejects pre-existing evidence paths inside the target, and writes JSON plus diagnostic-bearing SARIF before applying the threshold. Vite bundles the TypeScript parser into one CommonJS artifact; only Node built-ins remain external. CI regenerates that artifact byte-for-byte and executes it without `node_modules` resolution.

The JSON Schemas live at [`schemas/report.schema.json`](../schemas/report.schema.json), [`schemas/comparison.schema.json`](../schemas/comparison.schema.json), [`schemas/signed-report.schema.json`](../schemas/signed-report.schema.json), [`schemas/artifact-snapshot.schema.json`](../schemas/artifact-snapshot.schema.json), and [`schemas/capability-graph.schema.json`](../schemas/capability-graph.schema.json). The Codex harness uses a separately versioned TypeScript domain and a bounded delta-input reader; a standalone JSON Schema for its deeply nested snapshot and delta documents is not included in v0.7.0. SARIF output targets 2.1.0 and carries scan provenance in its run properties.

## Dependency policy

The production package uses TypeScript for source parsing, YAML for Skill front matter, and smol-toml for inert Codex configuration parsing. Node built-ins provide argument parsing, hashing, filesystem access, URL parsing, and output. Build tooling stays in development dependencies and every dependency is exact-pinned in the lockfile. The GitHub Action bundle vendors the MCP scanner and TypeScript; artifact, harness, and capability-graph commands ship in the CLI package but are not exposed as Action inputs.
