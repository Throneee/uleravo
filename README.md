# Uleravo

Uleravo is an evidence-first security scanner for Model Context Protocol servers. It finds a narrow set of high-impact problems, reports the source location and redacted evidence that triggered each finding, and produces reports that humans and CI systems can use without executing the target.

This repository contains the local scanner, its stable report contract, and the completed research foundation: reproducible provenance, deterministic rescan comparison, offline signed-report verification, and a bundled GitHub Action. The current deliverable remains a focused MCP analyzer. The approved product direction is a quiet trust layer for agent capabilities, developed without delaying release of the useful scanner that already exists.

Uleravo is the public-beta name after a preliminary exact, near-name, namespace, common-law, package-registry, domain, and multilingual knockout. This is launch-stage screening, not formal trademark advice; obtain Saudi and international counsel review before filing or major paid promotion.

## Product status

- **Ready for public beta:** the reviewed v0.6.3 CLI package and bundled GitHub Action source have passed their local release gates.
- **Launch operation pending in this snapshot:** create and push the public GitHub remote, then promote the production-site release. If you are reading this on the public GitHub repository, the remote step is complete.
- **Unreleased v0.7 foundation:** Agent Skill and Plugin identity snapshots plus one Codex local-configuration harness and semantic permission delta.
- **Next:** correlate artifact identity with harness exposure, then add advisory trust decisions without claiming runtime enforcement.
- **Not current capabilities:** hosted monitoring, organization policy, a trusted enforcement boundary, a dashboard, or runtime protection.

The release core is licensed Apache-2.0 and ships from the exact disclosure-safe export described by `release/public-export.json`. The GitHub Action uses immutable commit pins, and the default `pnpm check` gate includes the separate publication check. External availability begins when this exact history is pushed to the public remote. Do not interpret the future product direction as a claim that those capabilities already exist.

### Unreleased v0.7 developer branch

The `codex/v0.7-plugin-artifacts` branch contains additive, local-only Agent Skill and OpenAI Plugin identity snapshots plus the first Codex local-configuration harness. The artifact adapters record bounded raw-byte closures and declared identity without executing Skill code, Plugin hooks, or MCP servers. The Codex harness parses user `config.toml`, trusted project `.codex/config.toml`, and optional system `requirements.toml` strictly as data; it inventories declared Skills, Plugins, Apps, MCP servers, tools, hooks, filesystem/network scope, and approval posture, then produces a directional semantic permission delta. It never starts Codex or a configured capability and explicitly withholds complete effective-runtime claims when defaults, profiles, session flags, cloud requirements, or runtime discovery are unavailable. This is unreleased development evidence under the retained `0.6.3` package version, not part of the reviewed v0.6.3 package or a trust decision. See [the artifact snapshot contract](docs/v0.7-artifact-snapshots.md) and [the Codex harness contract](docs/v0.7-codex-harness.md).

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

Use the [rule guide](docs/rules.md) to understand each detector's trigger, safe patterns, and precision boundary. Use the [result-reporting guide](docs/reporting-results.md) to submit a correction without exposing private source or scanner evidence.

### Current limits

Uleravo v0.6.x is static analysis for MCP implementations. It does not analyze Agent Skills or Agent Plugins, inventory an agent harness, observe runtime behavior, establish publisher identity, prove that a deployed endpoint matches reviewed source, or issue a universal security certification.

JavaScript and TypeScript analysis follows only the documented one-hop import case; Python analysis is primarily intraprocedural. Medium-confidence filesystem and outbound-request findings may require review. A complete scan means the selected inputs were processed without error diagnostics under the documented analyzer coverage. It does not mean every vulnerability class was analyzed.

Launch materials also cite 25 pinned cases used as internal validation evidence. The corpus target set, methodology, and result records are deliberately outside this public export, so that evidence is not a publicly reproducible benchmark.

## Install the free beta

Requirements: Node.js 22.13 or newer. Download `uleravo-0.6.3.tgz` and `uleravo-0.6.3.tgz.sha256` from the [official Uleravo launch site](https://uleravo.babanosh.chatgpt.site/), verify the archive, then install and scan locally:

```bash
sha256sum --check uleravo-0.6.3.tgz.sha256
npm install --global ./uleravo-0.6.3.tgz
uleravo scan ./path/to/mcp-server
```

Published archives are immutable. The v0.6.2 archive and checksum remain available under their original filenames; v0.6.3 is a separate patch release.

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

The repository includes a Node 24 Action that runs the same scanner without installing dependencies or executing target code. The [observation workflow template](examples/github-actions/uleravo-observe.yml) is publication-ready and pins Uleravo to reviewed Commit A, `63f52dadd65960a873aa14067ab014f950fc4ec5`. The default `pnpm check` gate includes `pnpm check:publication`, which requires that product pin and full 40-hex SHAs for every Action before tagging or publication. The template disables persisted checkout credentials, scans pull requests and pushes to `main`, and requests 30-day retention for redacted JSON and SARIF evidence.

After the first run, use the job summary to confirm completeness, download the evidence artifact, and review critical and high findings first. The [redacted sample report](examples/reports/uleravo.sample.json), generated from a deliberately vulnerable [synthetic target](examples/reports/sample-target/src/index.ts), shows the report fields without exposing real project data.

The scanner uses `fail-on: none`, so findings do not fail an observation run. A complete run with findings publishes `outcome: passed` and `has-findings: true`; `outcome` preserves the configured threshold result, while `has-findings` describes the evidence and `threshold-exceeded` describes enforcement. Error diagnostics discovered after report planning publish `outcome: error` and fail closed with exit code `2`; earlier configuration, path-planning, or report-writing failures can exit `2` before outputs exist. Never interpret a zero finding count as clean unless `scan-complete` is also `true`. The evidence step runs with `if: always()` and treats a run with no reports as an error. The default template retains SARIF as an artifact without granting pull-request workflow code permission to write Code Scanning state; the Action reference documents a deliberately untrusted, best-effort annotation opt-in.

Observation mode is not a trusted baseline or new-finding enforcement boundary. GitHub shows a SARIF result as a pull-request check annotation only when every reported line is in the pull-request diff and on added or edited lines. Because Uleravo reports the sink that received untrusted input, a changed caller reaching an unchanged sink can fall outside that view. The retained reports remain the complete Uleravo evidence.

Uleravo's scanner and Action do not initiate network requests, use `GITHUB_TOKEN`, or print finding evidence into workflow logs. The example's checkout and artifact-upload steps are separate networked GitHub Actions. At this local launch snapshot, creating and pushing `Throneee/uleravo` is still an operator step, so the pinned reference cannot resolve externally yet; if you are reading this from that public GitHub repository, the dependency is complete and the template is ready to copy. See [the GitHub Action reference](docs/github-action.md) for setup, first-result triage, inputs, outputs, and the exact workspace boundary.

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
