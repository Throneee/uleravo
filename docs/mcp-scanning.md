# MCP scanning and released installation

[Candidate Skill review walkthrough](../README.md#start-here-review-one-skill) · [GitHub Action reference](github-action.md)

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

### Current limits

The MCP lane remains the v0.6.3 static analyzer. Artifact snapshots identify bounded local Skill or Codex Plugin bytes and declared metadata, but do not recursively analyze instructions, execute components, establish publisher identity, or prove that a deployed endpoint matches reviewed source. The Codex harness and Skill capability graph record supported local declarations, not effective runtime state. `not-declared` means no exact declaration was found in the safely captured applicable configuration; it does not rule out runtime discovery or defaults. Uleravo does not observe runtime behavior, enforce effect authority, or issue a universal security certification.

JavaScript and TypeScript analysis follows only the documented one-hop import case; Python analysis is primarily intraprocedural. Medium-confidence filesystem and outbound-request findings may require review. A complete scan means the selected inputs were processed without error diagnostics under the documented analyzer coverage. It does not mean every vulnerability class was analyzed.

Launch materials also cite 25 pinned cases used as internal validation evidence. The corpus target set, methodology, and result records are deliberately outside this public export, so that evidence is not a publicly reproducible benchmark.

## Install the released v0.7.0 beta

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

Compare MCP scan reports:

```bash
uleravo compare baseline.json current.json --fail-on high
```

Comparison treats finding fingerprints as a multiset and deterministically reports added, resolved, and unchanged findings. `--fail-on` applies only to added findings, so accepted baseline debt does not keep failing every run. Use `--format json` for automation.

Create an Ed25519 key pair, sign an MCP scan report, and verify it offline:

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

The repository includes a Node 24 Action that runs the MCP scanner without installing dependencies or executing target code. The [observation workflow template](../examples/github-actions/uleravo-observe.yml) pins Uleravo and both third-party Actions to reviewed full 40-hex commit SHAs. The v0.7.0 template pins reviewed product commit `81967c579878fe5dd245bd67a5238e0c5d6ce42f`. The default `pnpm check` gate validates the reference shape; the v0.7.0 release gate is `node scripts/check-publication-ready.mjs --expected-product-sha 81967c579878fe5dd245bd67a5238e0c5d6ce42f`, so a syntactically valid stale product pin cannot pass. The template disables persisted checkout credentials, scans pull requests and pushes to `main`, and requests 30-day retention for redacted JSON and SARIF evidence.

After the first run, use the job summary to confirm completeness, download the evidence artifact, and review critical and high findings first. The [redacted sample report](../examples/reports/uleravo.sample.json), generated from a deliberately vulnerable [synthetic target](../examples/reports/sample-target/src/index.ts), shows the report fields without exposing real project data.

The scanner uses `fail-on: none`, so findings do not fail an observation run. A complete run with findings publishes `outcome: passed` and `has-findings: true`; `outcome` preserves the configured threshold result, while `has-findings` describes the evidence and `threshold-exceeded` describes enforcement. Error diagnostics discovered after report planning publish `outcome: error` and fail closed with exit code `2`; earlier configuration, path-planning, or report-writing failures can exit `2` before outputs exist. Never interpret a zero finding count as clean unless `scan-complete` is also `true`. The evidence step runs with `if: always()` and treats a run with no reports as an error. The default template retains SARIF as an artifact without granting pull-request workflow code permission to write Code Scanning state; the Action reference documents a deliberately untrusted, best-effort annotation opt-in.

Observation mode is not a trusted baseline or new-finding enforcement boundary. GitHub shows a SARIF result as a pull-request check annotation only when every reported line is in the pull-request diff and on added or edited lines. Because Uleravo reports the sink that received untrusted input, a changed caller reaching an unchanged sink can fall outside that view. The retained reports remain the complete Uleravo evidence.

Uleravo's scanner and Action do not initiate network requests, use `GITHUB_TOKEN`, or print finding evidence into workflow logs. The example's checkout and artifact-upload steps are separate networked GitHub Actions. See [the GitHub Action reference](github-action.md) for setup, first-result triage, inputs, outputs, and the exact workspace boundary.

The CLI returns `0` when the configured threshold passes, `1` when findings meet `--fail-on`, and `2` for usage, scan, or rule failures.

## Deliberate safety boundary

Uleravo does not start the target server, import its code, contact its URLs, run package scripts, invoke `git`, or upload source. It intentionally ignores dependency trees and conventional build output and never follows symlinks. A discovered symlink, unresolved Git LFS source pointer, absent or unmaterialized declared submodule, scannable file that cannot be decoded or exceeds its byte limit, exhausted candidate or 100 MB aggregate-input budget, target with no scannable files, or scan that attempts to exceed the 5,000 raw-finding bound produces an error diagnostic and exit code `2`. A rule crash has the same fail-closed behavior; none of these cases can silently become a clean report.

Comparison and signed-envelope inputs are also untrusted. The CLI accepts only regular, bounded UTF-8 files and validates every report or envelope field it uses before producing output. Signed payloads are capped at 10 MB, use canonical base64url, and must decode to Uleravo's normalized JSON form.

Credential ranges are redacted from the full source line before evidence is shortened, fingerprinted, or serialized. Complete inline and multiline private-key blocks, source-derived paths and metadata, finding messages, and diagnostics pass through the same format-wide boundary. Terminal-control and bidirectional-control characters are rendered as visible code-point markers. Long-line evidence is cropped around the actual finding only after the full line is sanitized.

These controls make the scanner suitable for the proof and research phase. They do not turn static analysis into a runtime penetration test. See [the threat model](threat-model.md) for the exact limits.

## Accuracy policy

The scanner labels data-flow findings as medium confidence when it can see untrusted MCP input reach a filesystem or network sink but cannot prove the absence of a guard elsewhere. High-confidence rules require a direct, locally visible condition. A formatted Python URL with a literal HTTPS authority and only a variable path does not count as destination control. New rules need vulnerable and guarded fixtures before they ship.

JavaScript and TypeScript analysis is primarily intraprocedural. It follows exactly one module edge when a recognized MCP handler directly calls a top-level exported function from a static named relative ESM import. Import aliases, NodeNext-style `./logic.js` to `./logic.ts` resolution, parameter positions, and guarded basename paths are preserved. Default, namespace, CommonJS, dynamic, and package imports; re-exports; TypeScript path aliases; return flow; arbitrary helper graphs; and second-hop calls remain outside this boundary. Exceeding 1,000 unique imported call states produces an error diagnostic instead of silently returning a partial clean result.

Python analysis activates only for handlers decorated by an instance created from a top-level FastMCP or MCP Server import, or by a decorator imported directly from those modules. It resolves common import aliases and client objects, masks comments and non-formatted string contents, and never invokes Python. Local imports, custom registration wrappers, and interprocedural flow are outside the current precision boundary.

Generic credential detection requires a quoted source literal, or an unquoted value in an environment, YAML, or TOML assignment. Its broad placeholder heuristic suppresses candidates containing markers such as `fake`, `test`, `example`, `placeholder`, or `redacted`. Known provider-secret shapes remain reportable in test and example paths unless they are an exact documented provider example or their body is unmistakable repeated or sequential fixture filler. Formatted URL authorities are left to language-aware handler data flow because they do not prove a literal remote endpoint.

Package lockfiles apply only to `package.json` files in the same directory or a descendant directory. A root workspace lockfile therefore covers nested packages, while a lockfile in an unrelated sibling cannot suppress a mutable-package finding.

Suppressions are intentionally absent in Phase 1. The first real false-positive set will determine a narrow, auditable suppression format instead of committing the product to a speculative configuration surface.


`compare`, `sign`, and `verify` accept MCP scan evidence, not Skill graphs, graph comparisons, or review receipts. Use the candidate graph/review commands for those report types.
