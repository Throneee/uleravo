# Uleravo

Uleravo is an evidence-first local security tool for agent capabilities. It scans Model Context Protocol servers for a narrow set of high-impact problems, snapshots Agent Skill and Codex Plugin identity, inventories one bounded Codex configuration harness, and correlates exact Skill bytes to declarations without executing the target.

This repository contains the local scanner, its stable MCP report contract, deterministic Skill and Codex Plugin snapshots, a Codex harness snapshot and semantic permission delta, an exact-byte declared-exposure capability graph, reproducible provenance, offline signed-report verification, and a bundled MCP-focused GitHub Action. These are evidence inputs for human review, not a universal trust verdict or runtime enforcement boundary.

Uleravo is the public-beta name after a preliminary exact, near-name, namespace, common-law, package-registry, domain, and multilingual knockout. This is launch-stage screening, not formal trademark advice; obtain Saudi and international counsel review before filing or major paid promotion.

## Product status

- **Released v0.7.0 package:** Agent Skill and Codex Plugin identity snapshots, the v0.6.3 MCP analyzer, and one Codex local-configuration harness with semantic permission delta. The immutable public release does not include `capability-graph`.
- **Local unreleased candidate:** this checkout adds exact-byte declared Skill correlation through `capability-graph`; its package version remains 0.7.0 pending release preparation.
- **Public repository:** source and immutable releases are published at [`Throneee/uleravo`](https://github.com/Throneee/uleravo).
- **Compatibility:** the MCP analyzer remains version 0.6.3 so identical MCP inputs retain their established scan IDs; package, artifact-analyzer, and harness-analyzer versions are 0.7.0.
- **Next:** compare saved capability evidence and retain advisory review decisions without claiming runtime enforcement.
- **Not current capabilities:** hosted monitoring, organization policy, a trusted enforcement boundary, a dashboard, or runtime protection.

The release core is licensed Apache-2.0 and ships from the exact disclosure-safe export described by `release/public-export.json`. The GitHub Action uses immutable commit pins, and the default `pnpm check` gate includes the separate publication check. Do not interpret the future product direction as a claim that those capabilities already exist.

### v0.7 agent-security foundation

The artifact adapters record bounded raw-byte closures and declared identity without executing Skill code, Codex Plugin hooks, or MCP servers. The Codex harness parses user `config.toml`, trusted project `.codex/config.toml`, and optional system `requirements.toml` strictly as data; it inventories declared Skills, Codex Plugins, Apps, MCP servers, tools, hooks, filesystem/network scope, and approval posture, then produces a directional semantic permission delta. It never starts Codex or a configured capability and explicitly withholds complete effective-runtime claims when defaults, profiles, session flags, cloud requirements, or runtime discovery are unavailable. See [the artifact snapshot contract](docs/v0.7-artifact-snapshots.md) and [the Codex harness contract](docs/v0.7-codex-harness.md).

The local unreleased Skill capability graph takes one Skill root and those same bounded harness inputs. It reports only `declared-enabled`, `declared-disabled`, `not-declared`, or `unknown` for the exact captured bytes. It does not claim the Skill is installed, discoverable, reachable at runtime, initialized successfully, authorized to cause an effect, or trustworthy. Absolute host paths, configuration values, and artifact bytes are excluded from the graph. Safe, non-linked absolute user-config declarations are supported but never emitted; project-config absolute declarations outside the canonical project are resolved only when they exactly identify the supplied Skill root or its `SKILL.md` manifest. Uleravo treats relative user-config Skill paths as relative to that config's directory and relative project-config Skill paths as relative to the canonical project root. That is a conservative correlation convention, not a claim about undocumented Codex runtime path resolution; ambiguous, escaping, linked, changed, redacted, or otherwise unresolvable declarations fail closed as `unknown`, even when they appear unrelated because an alias cannot be excluded safely. A same-name Skill at another safely resolved root is `not-declared`, not an identity match. `DECLARATION_IDENTITY_MISMATCH` is reserved for the same canonical declared root failing exact-byte recapture. One exact declaration from an ignored or unknown layer, multiple exact declarations across any layers, or omitted exact-declaration enablement is `unknown`. Runtime discovery remains unobserved and out of scope; it does not change a complete captured-config conclusion of `not-declared` into a runtime claim.

Graph IDs are canonical over the exact Skill content digest, bound harness snapshot/input identity, adapter and schema versions, and normalized exact-declaration evidence. Reordering JSON object keys or addressing the same stable Skill/project root through a safe filesystem alias does not change them while the captured config bytes remain fixed. Changing declaration spelling changes the legacy harness input identity by design, so it also changes the bound graph identity.

Before inspecting a configured Skill leaf, correlation checks its directory ancestors in order on Windows and POSIX. A stable symbolic-link or junction prefix is rejected before accessing its descendants. Subsequent canonical-path and snapshot comparisons detect observed changes, but Node's portable path-based checks are not atomic: concurrent ancestor replacement can still cause a metadata lookup through a changed path. This is not a filesystem sandbox.

## What it does

Uleravo scans JavaScript, TypeScript, and Python MCP implementations, package manifests, MCP client configuration, and common text configuration. It currently detects:

| Rule | Risk | Default severity | Confidence |
|---|---|---:|---:|
| `MCP001` | Tool input reaches a shell interpreter | Critical | High |
| `MCP002` | Tool input selects an executable | High | High |
| `MCP003` | Tool input reaches a filesystem path | High | Medium |
| `MCP004` | Tool input controls an outbound URL | High | Medium |
| `MCP005` | Dynamic code evaluation in a handler | Critical | High |
| `MCP006` | Suspicious behavioral instructions in a tool description | High | High |
| `MCP007` | Hardcoded credential | High | High |
| `MCP008` | Cleartext remote HTTP transport | Medium | High |
| `MCP009` | Credential embedded in a URL | High | High |
| `MCP010` | Mutable package reference | Medium | High |
| `MCP011` | Complete host environment forwarded to a child process | Medium | High |
| `MCP012` | Destructive tool lacks `destructiveHint` | Low | Medium |

Every finding contains a stable fingerprint, source location, redacted evidence, confidence, remediation, and CWE / OWASP / MITRE ATLAS mappings where the mapping is defensible.

v0.7.0 also adds local, deterministic commands for agent artifacts and one harness:

```bash
uleravo snapshot ./path/to/skill --kind skill --format json
uleravo snapshot ./path/to/plugin --kind plugin --format json
uleravo harness ./path/to/project --format json --output current.harness.json
uleravo harness-delta baseline.harness.json current.harness.json --format text
```

The local unreleased candidate additionally supports:

```bash
uleravo capability-graph ./path/to/skill ./path/to/project \
  --user-config ./config.toml --format json --output skill.graph.json
```

For `capability-graph`, the project argument defaults to `.`. Harness-layer controls are `--user-config`, `--project-config`, and `--requirements`, with exact exclusion counterparts `--skip-user-config`, `--skip-project-config`, and `--skip-requirements`. Graph capture defaults are `--max-skill-file-bytes 10000000`, `--max-skill-files 1000`, and `--max-skill-total-bytes 50000000`. Exit `0` means the graph reached any definitive declared-exposure state, including `declared-disabled` or `not-declared`; `unknown`, incomplete evidence, unsafe/incomplete target capture, or invalid usage exits `2`. An unsafe or incomplete target capture produces no graph.

Excluding either declaration-bearing layer with `--skip-user-config` or `--skip-project-config` makes correlation `unknown` (exit `2`), even if an exact declaration exists in the other layer: the excluded layer might contain another declaration. This differs from an absent detected optional file. `--skip-requirements` alone does not force `unknown`, because requirements supply constraints rather than Skill declarations.

Use the [rule guide](docs/rules.md) to understand each detector's trigger, safe patterns, and precision boundary. Use the [result-reporting guide](docs/reporting-results.md) to submit a correction without exposing private source or scanner evidence.

### Current limits

The MCP lane remains the v0.6.3 static analyzer. Artifact snapshots identify bounded local Skill or Codex Plugin bytes and declared metadata, but do not recursively analyze instructions, execute components, establish publisher identity, or prove that a deployed endpoint matches reviewed source. The Codex harness and Skill capability graph record supported local declarations, not effective runtime state. `not-declared` means no exact declaration was found in the safely captured applicable configuration; it does not rule out runtime discovery or defaults. Uleravo does not observe runtime behavior, enforce effect authority, or issue a universal security certification.

JavaScript and TypeScript analysis follows only the documented one-hop import case; Python analysis is primarily intraprocedural. Medium-confidence filesystem and outbound-request findings may require review. A complete scan means the selected inputs were processed without error diagnostics under the documented analyzer coverage. It does not mean every vulnerability class was analyzed.

Launch materials also cite 25 pinned cases used as internal validation evidence. The corpus target set, methodology, and result records are deliberately outside this public export, so that evidence is not a publicly reproducible benchmark.

## Install the free beta

Requirements: Node.js 22.13 or newer. Download `uleravo-0.7.0.tgz` and `uleravo-0.7.0.tgz.sha256` from the [v0.7.0 GitHub release](https://github.com/Throneee/uleravo/releases/tag/v0.7.0), verify the archive, then install it locally:

```bash
sha256sum --check uleravo-0.7.0.tgz.sha256
npm install --global ./uleravo-0.7.0.tgz
uleravo scan ./path/to/mcp-server
```

Published archives are immutable. The v0.6.2 and v0.6.3 archives and checksums remain available under their original filenames; v0.7.0 is a separate release and does not replace those bytes.

For source development, use pnpm 11 with `pnpm install --frozen-lockfile` and `pnpm build`.

Fail CI only for high and critical findings:

```bash
uleravo scan . --fail-on high
```

Create a SARIF report:

```bash
uleravo scan . --format sarif --output uleravo.sarif
```

Create a machine-readable JSON report:

```bash
uleravo scan . --format json --output uleravo.json
```

Attach an explicit repository identity in CI:

```bash
uleravo scan . \
  --format json \
  --output current.json \
  --repository-url "https://github.com/${GITHUB_REPOSITORY}" \
  --commit-sha "${GITHUB_SHA}"
```

The JSON report records the exact commit and URL supplied by CI, package name and version when present, SHA-256 state for recognized lockfiles, and a SHA-256 digest of the normalized, admitted scan inputs. If analysis stops at a safety limit, that digest can include decoded inputs that were not fully rule-analyzed; the report is marked incomplete. Repository identity is never inferred by executing `git` or reading hidden VCS state. URLs containing credentials are rejected.

Compare a baseline with a current report:

```bash
uleravo compare baseline.json current.json --fail-on high
```

Comparison treats finding fingerprints as a multiset and deterministically reports added, resolved, and unchanged findings. `--fail-on` applies only to added findings, so accepted baseline debt does not keep failing every run. Use `--format json` for automation.

Create an Ed25519 key pair, sign a JSON report, and verify it offline:

```bash
uleravo keygen \
  --private-key uleravo-signing-key.pem \
  --public-key uleravo-signing-key.pub.pem

uleravo sign uleravo.json \
  --private-key uleravo-signing-key.pem \
  --output uleravo.signed.json

uleravo verify uleravo.signed.json \
  --public-key uleravo-signing-key.pub.pem \
  --output verified.json
```

Key generation never overwrites an existing file. On POSIX systems, signing rejects private keys that are readable by group or other users. The envelope signs Uleravo's normalized, redacted report bytes and records their SHA-256 plus the full SHA-256 fingerprint of the public key. Verification checks all three and can recover the normalized report. Canonical v0.5.3 schema-1 payloads are authenticated against their original bytes before stronger current redaction is applied to the recovered copy.

Keep the private key out of source control and distribute the public key through a trusted channel. A valid signature proves that the matching key signed the report; it does not identify who controls that key or prove that the recorded source was actually scanned.

## GitHub Action

The repository includes a Node 24 Action that runs the MCP scanner without installing dependencies or executing target code. The [observation workflow template](examples/github-actions/uleravo-observe.yml) pins Uleravo and both third-party Actions to reviewed full 40-hex commit SHAs. The v0.7.0 template pins reviewed product commit `81967c579878fe5dd245bd67a5238e0c5d6ce42f`. The default `pnpm check` gate validates the reference shape; the v0.7.0 release gate is `node scripts/check-publication-ready.mjs --expected-product-sha 81967c579878fe5dd245bd67a5238e0c5d6ce42f`, so a syntactically valid stale product pin cannot pass. The template disables persisted checkout credentials, scans pull requests and pushes to `main`, and requests 30-day retention for redacted JSON and SARIF evidence.

After the first run, use the job summary to confirm completeness, download the evidence artifact, and review critical and high findings first. The [redacted sample report](examples/reports/uleravo.sample.json), generated from a deliberately vulnerable [synthetic target](examples/reports/sample-target/src/index.ts), shows the report fields without exposing real project data.

The scanner uses `fail-on: none`, so findings do not fail an observation run. A complete run with findings publishes `outcome: passed` and `has-findings: true`; `outcome` preserves the configured threshold result, while `has-findings` describes the evidence and `threshold-exceeded` describes enforcement. Error diagnostics discovered after report planning publish `outcome: error` and fail closed with exit code `2`; earlier configuration, path-planning, or report-writing failures can exit `2` before outputs exist. Never interpret a zero finding count as clean unless `scan-complete` is also `true`. The evidence step runs with `if: always()` and treats a run with no reports as an error. The default template retains SARIF as an artifact without granting pull-request workflow code permission to write Code Scanning state; the Action reference documents a deliberately untrusted, best-effort annotation opt-in.

Observation mode is not a trusted baseline or new-finding enforcement boundary. GitHub shows a SARIF result as a pull-request check annotation only when every reported line is in the pull-request diff and on added or edited lines. Because Uleravo reports the sink that received untrusted input, a changed caller reaching an unchanged sink can fall outside that view. The retained reports remain the complete Uleravo evidence.

Uleravo's scanner and Action do not initiate network requests, use `GITHUB_TOKEN`, or print finding evidence into workflow logs. The example's checkout and artifact-upload steps are separate networked GitHub Actions. See [the GitHub Action reference](docs/github-action.md) for setup, first-result triage, inputs, outputs, and the exact workspace boundary.

The CLI returns `0` when the configured threshold passes, `1` when findings meet `--fail-on`, and `2` for usage, scan, or rule failures.

## Deliberate safety boundary

Uleravo does not start the target server, import its code, contact its URLs, run package scripts, invoke `git`, or upload source. It intentionally ignores dependency trees and conventional build output and never follows symlinks. A discovered symlink, unresolved Git LFS source pointer, absent or unmaterialized declared submodule, scannable file that cannot be decoded or exceeds its byte limit, exhausted candidate or 100 MB aggregate-input budget, target with no scannable files, or scan that attempts to exceed the 5,000 raw-finding bound produces an error diagnostic and exit code `2`. A rule crash has the same fail-closed behavior; none of these cases can silently become a clean report.

Comparison and signed-envelope inputs are also untrusted. The CLI accepts only regular, bounded UTF-8 files and validates every report or envelope field it uses before producing output. Signed payloads are capped at 10 MB, use canonical base64url, and must decode to Uleravo's normalized JSON form.

Credential ranges are redacted from the full source line before evidence is shortened, fingerprinted, or serialized. Complete inline and multiline private-key blocks, source-derived paths and metadata, finding messages, and diagnostics pass through the same format-wide boundary. Terminal-control and bidirectional-control characters are rendered as visible code-point markers. Long-line evidence is cropped around the actual finding only after the full line is sanitized.

These controls make the scanner suitable for the proof and research phase. They do not turn static analysis into a runtime penetration test. See [the threat model](docs/threat-model.md) for the exact limits.

## Accuracy policy

The scanner labels data-flow findings as medium confidence when it can see untrusted MCP input reach a filesystem or network sink but cannot prove the absence of a guard elsewhere. High-confidence rules require a direct, locally visible condition. A formatted Python URL with a literal HTTPS authority and only a variable path does not count as destination control. New rules need vulnerable and guarded fixtures before they ship.

JavaScript and TypeScript analysis is primarily intraprocedural. It follows exactly one module edge when a recognized MCP handler directly calls a top-level exported function from a static named relative ESM import. Import aliases, NodeNext-style `./logic.js` to `./logic.ts` resolution, parameter positions, and guarded basename paths are preserved. Default, namespace, CommonJS, dynamic, and package imports; re-exports; TypeScript path aliases; return flow; arbitrary helper graphs; and second-hop calls remain outside this boundary. Exceeding 1,000 unique imported call states produces an error diagnostic instead of silently returning a partial clean result.

Python analysis activates only for handlers decorated by an instance created from a top-level FastMCP or MCP Server import, or by a decorator imported directly from those modules. It resolves common import aliases and client objects, masks comments and non-formatted string contents, and never invokes Python. Local imports, custom registration wrappers, and interprocedural flow are outside the current precision boundary.

Generic credential detection requires a quoted source literal, or an unquoted value in an environment, YAML, or TOML assignment. Its broad placeholder heuristic suppresses candidates containing markers such as `fake`, `test`, `example`, `placeholder`, or `redacted`. Known provider-secret shapes remain reportable in test and example paths unless they are an exact documented provider example or their body is unmistakable repeated or sequential fixture filler. Formatted URL authorities are left to language-aware handler data flow because they do not prove a literal remote endpoint.

Package lockfiles apply only to `package.json` files in the same directory or a descendant directory. A root workspace lockfile therefore covers nested packages, while a lockfile in an unrelated sibling cannot suppress a mutable-package finding.

Suppressions are intentionally absent in Phase 1. The first real false-positive set will determine a narrow, auditable suppression format instead of committing the product to a speculative configuration surface.

## Development

```bash
pnpm check
```

The quality gate runs formatting and lint checks, strict TypeScript validation, tests with coverage thresholds, a production build, byte-for-byte Action bundle regeneration, validation of the exact content-hashed public-export allowlist, and the final immutable-pin publication check. The current suite exercises ESM and CommonJS imports, paired one-hop cross-file vulnerabilities and guards, Python decorators and multiline syntax, direct and aliased handlers, taint propagation, guarded paths, report redaction, provenance validation, binary lockfiles, multiset comparison, untrusted report parsing, signed-report tampering and key handling, Action workspace confinement, stable fingerprints, symlink handling, file limits, and all output formats. `scan:self` excludes the test tree and the exact deliberately vulnerable sample target; a dedicated release test rescans that target and binds the published sample's findings, provenance, and scan ID.

The public release architecture is documented in [architecture](docs/architecture.md), and the scanner's security boundaries are documented in the [threat model](docs/threat-model.md). Use the [rule guide](docs/rules.md) for detector behavior, the [result-reporting guide](docs/reporting-results.md) for sanitized corrections, and the [security policy](SECURITY.md) for private vulnerability reports.

## License

The public scanner core is licensed under the [Apache License 2.0](LICENSE). The bundled GitHub Action includes TypeScript 6.0.3 and third-party material documented in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES). Proprietary hosted-service code is kept outside this licensed release surface.
