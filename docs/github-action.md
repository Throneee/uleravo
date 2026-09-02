# GitHub Action

The root [`action.yml`](../action.yml) packages Uleravo as a Node 24 JavaScript Action. Its committed `action/dist/index.cjs` bundle contains the scanner and its only runtime dependency. It needs no install step and performs no network request.

## Start in observation mode

The reviewed [observation workflow template](../examples/github-actions/uleravo-observe.yml) is publication-ready. It pins Uleravo to reviewed Commit A, `63f52dadd65960a873aa14067ab014f950fc4ec5`, and pins both third-party Actions to full 40-hex SHAs. The default `pnpm check` gate includes `pnpm check:publication`, which requires exactly those three full-SHA Action references and exactly one `Throneee/uleravo` reference. At this local launch snapshot, creating and pushing the public `Throneee/uleravo` remote is still an operator step, so the product pin cannot resolve externally until that exact history is published; if you are reading this from the public repository, that condition is complete. Change `main` under `push.branches` if the consuming repository uses another default branch. The template scans pull requests and default-branch pushes and requests 30-day retention for the JSON and SARIF evidence.

The scanner step deliberately uses `fail-on: none` and does **not** use `continue-on-error`. Findings therefore remain observational, while invalid configuration, incomplete discovery, report-writing failures, and error diagnostics still fail the job. The artifact step runs with `if: always()` so reports written before a failure are preserved. It also uses `if-no-files-found: error`; a run that produces no evidence must not look successful.

The default template is artifact-first. It grants only `contents: read` and does not give pull-request-controlled workflow code permission to write Code Scanning state. Uleravo's step summary provides counts and a complete/incomplete status; the retained reports carry the redacted finding evidence.

This is intentionally **not a trusted enforcement boundary**. A normal `pull_request` workflow is controlled by the pull request's workflow definition, so a contributor can change or remove the scan and its inputs. Immutable Action pins and explicit permissions reduce accidental drift and impact, but do not make the result authoritative. The reports are evidence from that run, not authorization to merge.

Uleravo itself remains offline: it reads the checked-out workspace and writes local reports without making network requests. The pinned checkout and artifact uploader actions communicate with GitHub; they do not grant Uleravo more authority.

### Review your first run

1. Open the Uleravo job summary and confirm that the scan is complete.
2. Download the `uleravo-evidence-*` artifact from the workflow run.
3. Open `uleravo.json` and review critical and high findings first. The [redacted sample report](../examples/reports/uleravo.sample.json), generated from a deliberately vulnerable [synthetic target](../examples/reports/sample-target/src/index.ts), shows the fields and ordering.
4. Use each finding's `ruleId`, `file`, `line`, `confidence`, redacted `evidence`, and `remediation` fields to reproduce and triage it against the source.
5. If any error diagnostic exists, treat the evidence as incomplete even when the finding count is zero.

The result contract is:

| Scan state | Findings | Step result | Meaning |
| --- | ---: | --- | --- |
| Complete | 0 | Pass | No supported finding was detected |
| Complete observation | More than 0 | Pass | Findings exist and require review |
| Complete enforcement | Threshold met | Fail, exit 1 | Reports are valid and the configured threshold was exceeded |
| Incomplete | Any | Fail, exit 2 | Never interpret the result as clean |

Do not automate from `outcome` alone. Check `scan-complete`, `has-findings`, and `threshold-exceeded` according to the decision being made. See the [rule guide](rules.md) for detector boundaries and [result-reporting guide](reporting-results.md) for safe corrections.

### Optional Code Scanning annotations

Eligible repositories can opt into GitHub's Code Scanning view by adding `actions: read` and `security-events: write` to the workflow permissions and appending this step to the scan job:

```yaml
      - name: Upload SARIF to Code Scanning
        if: ${{ always() && hashFiles('uleravo-results/uleravo.sarif') != '' }}
        continue-on-error: true
        uses: github/codeql-action/upload-sarif@cdf488f595d80d6e07e03d4674febd5ab45fa938 # v4.37.9
        with:
          sarif_file: uleravo-results/uleravo.sarif
          category: uleravo
```

That permission lets the pull-request workflow write Code Scanning state, and the pull request can change the workflow. Treat its annotations as untrusted observation only. Fork tokens may be downgraded and private repositories need an eligible GitHub plan and security configuration, so this best-effort step may not publish annotations. GitHub also limits pull-request annotations to added or edited lines; a changed caller reaching an unchanged helper sink can be absent from the native PR view even though it remains in Uleravo's report.

### Advisory threshold signal

A trusted-contributor repository with no accepted findings at its chosen threshold can change `fail-on: none` to `fail-on: high` while keeping the evidence-retention step. This makes the scan step return `1` for every current high or critical finding. It is still bypassable by a pull request that changes the workflow, so do not present it as an authoritative security control or use it to claim new-finding-only enforcement.

Repositories with accepted debt should remain in observation mode until Uleravo has a trusted base/head comparison. That future workflow, policy, scanner pin, and baseline must come from protected default-branch context or an external enforcement boundary, never the untrusted pull-request checkout.

## Inputs

| Input | Default | Behavior |
| --- | --- | --- |
| `target` | `.` | File or directory inside `GITHUB_WORKSPACE` |
| `fail-on` | `none` | `none`, `info`, `low`, `medium`, `high`, or `critical` |
| `output` | `uleravo.json` | Workspace-relative JSON report path |
| `sarif-output` | `uleravo.sarif` | Workspace-relative SARIF report path |
| `exclude` | empty | Newline-separated target-relative paths |
| `max-file-bytes` | `1000000` | Per-file byte limit from 1 to 100000000 |

The two output files must be separate, non-overlapping paths; Uleravo also rejects NFC/lowercase aliases before creating either parent directory. Existing files outside the scan target are replaced atomically with mode `0600` where POSIX modes are supported. An output path inside the target must not already exist: rejecting it prevents a committed file from being silently excluded and overwritten. Before creating a missing output directory, Uleravo resolves its nearest existing ancestor and rejects any link outside the real workspace boundary. It also rejects absolute paths, parent traversal, target overwrite (including an NFC/lowercase alias), a target that resolves outside the workspace, and output-directory symlinks that leave it. Portable output validation rejects Windows device names, alternate-data-stream syntax, and segments ending in a dot or space on every host.

The Action retains at most 100 MB across decoded scan inputs and hashed lockfiles and considers at most 10,000 candidate files. These aggregate limits are fixed safety boundaries; narrow the target or use explicit exclusions if a repository exceeds them.

Uleravo also retains at most 5,000 raw findings before deduplication. Attempting to exceed that bound preserves the first deterministic set, emits an error diagnostic, and fails the scan as incomplete instead of constructing an unbounded report.

The example checkout does not fetch Git LFS objects or submodules. If the selected target intentionally includes either, materialize them in the checkout step:

```yaml
        with:
          persist-credentials: false
          lfs: true
          submodules: recursive
```

An unresolved LFS pointer in a supported source file, or a declared submodule that is absent or empty, makes the evidence incomplete. Uleravo detects these states locally and never invokes `git` or fetches the missing content itself.

The Action automatically records `${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}` and the complete `GITHUB_SHA` as explicit repository provenance. The default checkout action checks out that identity. If a workflow later replaces the workspace with a different revision, its provenance no longer describes the replacement; run Uleravo before such a step.

## Outputs

| Output | Value |
| --- | --- |
| `outcome` | `passed` when the configured threshold passes, `findings` when it is exceeded, or `error` for an incomplete scan |
| `findings` | Total finding count |
| `has-findings` | `true` when the report contains at least one finding; check `scan-complete` separately |
| `critical`, `high`, `medium`, `low`, `info` | Counts by severity |
| `scan-id` | Deterministic scan identifier |
| `report` | Workspace-relative JSON path |
| `sarif` | Workspace-relative SARIF path |
| `scan-complete` | `true` exactly when the scan has zero error diagnostics |
| `error-diagnostics` | Number of error diagnostics |
| `warning-diagnostics` | Number of warning diagnostics |
| `threshold-exceeded` | `true` when a finding meets `fail-on`; always `false` for `fail-on: none` |

`outcome` preserves the configured threshold result for compatibility; it is not a zero-finding signal. A complete observation with findings publishes `outcome: passed` and `has-findings: true`, then exits `0` under `fail-on: none`. `has-findings: false` is not a clean result unless `scan-complete` is also `true`. Action outputs are published only after both reports are written; an earlier configuration, path-planning, or report-write exception still exits `2` but may not create output records. Exit code `0` means the scan completed below the threshold. Exit code `1` means findings met the configured threshold. Exit code `2` means configuration, discovery, report writing, or scan diagnostics failed. Empty or unsupported targets and scannable inputs skipped for encoding, symlink, or resource-limit reasons fail closed. JSON and SARIF are written before scan-diagnostic or threshold failures so later `if: always()` steps can preserve them. SARIF records diagnostics as tool execution notifications and marks the invocation unsuccessful when any error makes evidence incomplete.

## Distribution integrity

`pnpm build:action` regenerates the single-file bundle. `pnpm check:action` rebuilds into a temporary directory and requires byte-for-byte equality with the committed artifact. CI runs the bundle itself after this drift check on Node 24 and separately tests the package's Node 22.13 minimum.

The Action requires a runner that supports Node 24 JavaScript Actions. It intentionally avoids the Actions toolkit because it does not need API access. It writes numeric summaries to the runner command files and never echoes source-derived finding evidence into logs.
