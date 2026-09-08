# Uleravo

Capture a Skill's declared exposure, compare fresh evidence with a reviewed baseline, and retain the review locally. Uleravo reads bounded local files without executing the target or uploading source. Captured declarations and advisory reviews are evidence for a person; they do not establish runtime behavior, safety, or enforcement.

**Public release candidate: `0.8.0-rc.1`.** Download the [candidate archive](https://uleravo.com/downloads/uleravo-0.8.0-rc.1.tgz) and [SHA-256 checksum](https://uleravo.com/downloads/uleravo-0.8.0-rc.1.tgz.sha256), save them together, then verify and install below. This is a release candidate distributed as an archive; it is not published to the npm registry.

[0.8.0-rc.1 release notes](https://github.com/Throneee/uleravo/blob/main/docs/releases/0.8.0-rc.1.md) · [MCP scanning and prior v0.7.0 installation](docs/mcp-scanning.md) · [GitHub Action](docs/github-action.md) · [Skill evidence contracts and limits](docs/skill-review.md)

The accepted archive is immutable. Its bundled README retains the local/private candidate wording from before publication; the installation and synthetic walkthrough commands remain unchanged. Use this source README and the release notes for current availability.

## First local result: check project configuration (unreleased)

**Development addition, not present in the immutable public `0.8.0-rc.1` or local `0.9.0-rc.2` archives.** After installing a build that includes `check`, use the installed command from your project:

```sh
uleravo check                 # current directory; no account or user-wide reads
uleravo check "PATH/TO/PROJECT"
# Review the named local file/field, make a manual edit, then repeat the same command.
```

For a local npm installation, use `./node_modules/.bin/uleravo` (Windows PowerShell: `./node_modules/.bin/uleravo.cmd`) instead of `uleravo` if it is not on PATH. Run `uleravo check --help` to confirm the installed build supports it; the older archives above have not been changed.

The first screen lists actually covered **harness/project configuration groups**, then prioritized findings with title, severity, relative file/field, reason and manual next step. No hash copying, evidence-file selection, upload, credential lookup, watch or target execution. It reuses the monitoring capture and safe-locator pipeline for existing Claude Code, Cursor and Codex project settings—not a Skill malware detector or runtime protection.

Exit **1** means declarations need review; **0** means a complete covered review observed no supported findings, **not security or resolution**; **2** means invalid arguments/target, no coverage or incomplete review. Missing groups remain unobserved. A Skill-only or empty directory has no coverage. After a manual change, recheck the same project; there is no stored baseline or automatic edit. See [coverage and limits](docs/monitoring.md#quick-project-check-unreleased).

## Existing installed walkthrough: review one Skill

Requirements: a supported Node.js LTS runtime (**22.23.2 or newer on the 22.x line**, or **24.19.0 or newer on the 24.x line**) and npm. These are verified baselines, not a claim about the earliest fixed versions. Earlier Windows runtimes can return inconsistent file identity metadata; Uleravo keeps its reader fail-closed rather than ignoring that mismatch. See [runtime support](docs/monitoring.md#runtime-support). Existing downloaded archives remain unchanged; their older metadata does not supersede this compatibility finding. Start in the directory containing the archive and checksum sidecar. Installation may fetch pinned dependencies if they are absent from your cache; default analysis itself is local. No account, credential, running agent, or source checkout is needed for this synthetic walkthrough.

Choose one shell below. It installs into a fresh temporary consumer and copies the [packaged inert example](examples/skill-review/skill/SKILL.md). The separate synthetic user configuration explicitly disables that exact Skill. Its relative path resolves from the configuration's directory. The empty project has no optional `.codex/config.toml`; only system requirements are excluded. All reports are outside the Skill root.

<details open>
<summary>Windows PowerShell — install, capture, change, restore, and retain</summary>

```powershell
$ErrorActionPreference = 'Stop'
$candidate = (Resolve-Path './uleravo-0.8.0-rc.1.tgz').Path
$expected = ((Get-Content -LiteralPath "$candidate.sha256" -Raw).Trim() -split '\s+')[0]
$actual = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
if ($expected -notmatch '^[0-9a-fA-F]{64}$' -or $actual -ne $expected) { throw 'Candidate checksum mismatch.' }
$demo = Join-Path ([IO.Path]::GetTempPath()) ('uleravo-review-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path "$demo/consumer" | Out-Null
npm install --prefix "$demo/consumer" --ignore-scripts --no-audit --no-fund $candidate
if ($LASTEXITCODE -ne 0) { throw 'Candidate installation failed.' }
$uleravo = "$demo/consumer/node_modules/.bin/uleravo.cmd"
& $uleravo --version
# Expected: 0.8.0-rc.1
$example = "$demo/consumer/node_modules/uleravo/examples/skill-review"
Copy-Item -LiteralPath $example -Destination "$demo/workflow" -Recurse
New-Item -ItemType Directory -Path "$demo/workflow/project" | Out-Null
$config = "$demo/workflow/config.toml"
$capture = @('capability-graph', "$demo/workflow/skill", "$demo/workflow/project", '--user-config', $config, '--skip-requirements', '--format', 'json')

# 1. Capture and inspect the baseline. Retain it after reviewing the evidence.
& $uleravo @capture --output "$demo/baseline.graph.json"
& $uleravo capability-graph-compare "$demo/baseline.graph.json" "$demo/baseline.graph.json"
# Result: unchanged; complete: yes; declared-disabled -> declared-disabled.
& $uleravo review-record "$demo/baseline.graph.json" --format json --output "$demo/baseline.review.json"

# 2. Make one synthetic declaration change, then explain it.
[IO.File]::WriteAllText($config, ([IO.File]::ReadAllText($config).Replace('enabled = false', 'enabled = true')))
& $uleravo @capture --output "$demo/changed.graph.json"
& $uleravo capability-graph-compare "$demo/baseline.graph.json" "$demo/changed.graph.json"
# Result: changed; Skill bytes: same; declaration groups: different.
# Declared exposure: declared-disabled -> declared-enabled. Comparison exits 0.
& $uleravo review-check "$demo/baseline.review.json" "$demo/changed.graph.json"
if ($LASTEXITCODE -ne 1) { throw 'Expected changed-since-review (exit 1).' }

# 3. If the enablement was unintended, manually restore the original declaration.
# Here we copy the original synthetic config bytes, then capture again.
Copy-Item -LiteralPath "$example/config.toml" -Destination $config
& $uleravo @capture --output "$demo/restored.graph.json"
& $uleravo capability-graph-compare "$demo/baseline.graph.json" "$demo/restored.graph.json" --format json --output "$demo/restoration.comparison.json"
if ($LASTEXITCODE -ne 0) { throw 'Restoration comparison failed.' }
$restoration = Get-Content -LiteralPath "$demo/restoration.comparison.json" -Raw | ConvertFrom-Json
if (!$restoration.complete -or $restoration.status -ne 'unchanged') { throw 'Review the differences before retaining evidence.' }
# Captured evidence matches the original baseline. Explicitly retain this review:
& $uleravo review-record "$demo/restored.graph.json" --format json --output "$demo/restored.review.json"

# 4. Return later: ALWAYS capture again, then check the retained review.
& $uleravo @capture --output "$demo/current.graph.json"
& $uleravo review-check "$demo/restored.review.json" "$demo/current.graph.json"
if ($LASTEXITCODE -ne 0) { throw 'Review the current evidence and diagnostics.' }
# Review result: matches-evidence; exit 0. Earlier reports and receipts remain intact.
$demo
```

</details>

<details>
<summary>Ubuntu / POSIX shell — the same installed workflow</summary>

```sh
# Run in a shell session; fail on unexpected command errors.
set -eu
candidate="$(pwd)/uleravo-0.8.0-rc.1.tgz"
sha256sum --check uleravo-0.8.0-rc.1.tgz.sha256
demo="$(mktemp -d "${TMPDIR:-/tmp}/uleravo-review.XXXXXX")"
mkdir "$demo/consumer"
npm install --prefix "$demo/consumer" --ignore-scripts --no-audit --no-fund "$candidate"
uleravo="$demo/consumer/node_modules/.bin/uleravo"
"$uleravo" --version
# Expected: 0.8.0-rc.1
example="$demo/consumer/node_modules/uleravo/examples/skill-review"
cp -R "$example" "$demo/workflow"
mkdir "$demo/workflow/project"
config="$demo/workflow/config.toml"
capture() {
  "$uleravo" capability-graph "$demo/workflow/skill" "$demo/workflow/project" \
    --user-config "$config" --skip-requirements --format json --output "$1"
}

# 1. Capture, inspect, then explicitly retain the reviewed baseline.
capture "$demo/baseline.graph.json"
"$uleravo" capability-graph-compare "$demo/baseline.graph.json" "$demo/baseline.graph.json"
# Result: unchanged; complete: yes; declared-disabled -> declared-disabled.
"$uleravo" review-record "$demo/baseline.graph.json" --format json --output "$demo/baseline.review.json"

# 2. Change only the synthetic declaration, then explain the fresh evidence.
printf "[[skills.config]]\npath = './skill/SKILL.md'\nenabled = true\n" > "$config"
capture "$demo/changed.graph.json"
"$uleravo" capability-graph-compare "$demo/baseline.graph.json" "$demo/changed.graph.json"
# Result: changed; Skill bytes: same; declaration groups: different.
# Declared exposure: declared-disabled -> declared-enabled. Comparison exits 0.
review_exit=0
"$uleravo" review-check "$demo/baseline.review.json" "$demo/changed.graph.json" || review_exit=$?
test "$review_exit" -eq 1
# Expected: changed-since-review; exit 1.

# 3. If unintended, restore the original synthetic declaration and capture again.
cp "$example/config.toml" "$config"
capture "$demo/restored.graph.json"
"$uleravo" capability-graph-compare "$demo/baseline.graph.json" "$demo/restored.graph.json" \
  --format json --output "$demo/restoration.comparison.json"
node --input-type=module -e 'import fs from "node:fs"; const r = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); if (!r.complete || r.status !== "unchanged") throw new Error("Review the differences before retaining evidence.");' "$demo/restoration.comparison.json"
# Captured evidence matches the original baseline. Explicitly retain this review:
"$uleravo" review-record "$demo/restored.graph.json" --format json --output "$demo/restored.review.json"

# 4. Return later: ALWAYS capture again, then check the retained review.
capture "$demo/current.graph.json"
"$uleravo" review-check "$demo/restored.review.json" "$demo/current.graph.json"
# Review result: matches-evidence; exit 0. Earlier evidence remains intact.
printf '%s\n' "$demo"
```

</details>

Every later check needs a **fresh capture and new output filename**, for example `next.graph.json`. Reusing an old graph only checks old evidence. To repeat the entire demo, start with the install block again; it creates a new directory. Commands refuse to overwrite any existing report or receipt, so an output collision exits 2 and preserves earlier files. The example config edits are deliberate manual changes to synthetic input.

A byte-only edit to the copied `skill/SKILL.md`, followed by capture and comparison, reports `Skill bytes: different` even if declarations stay the same. Review the changed instructions locally; byte changes alone do not establish expanded capability. Malformed config or exclusion of a declaration layer yields `unknown`/`incomplete` and exit 2; resolve the side-specific diagnostics and recapture. An absent optional project config differs from deliberately using `--skip-project-config` or `--skip-user-config`, which forces unknown evidence. See the [full capture controls](docs/skill-review.md).

| Question | Command and input | Result / exit |
|---|---|---|
| What was declared for these exact Skill bytes? | `capability-graph` → graph JSON | Definitive enabled, disabled, or not-declared: 0. Unknown/incomplete: 2; unsafe target capture emits no graph. |
| What changed in captured evidence? | `capability-graph-compare baseline.graph.json current.graph.json` | Complete `unchanged` or `changed`: 0. `incomplete` or `version-limited`: 2. |
| Retain this caller-recorded review? | `review-record graph.json --format json --output reviewed.json` | Complete supported evidence recorded: 0. Invalid/ineligible evidence: 2. |
| Does supplied fresh evidence match the review? | `review-check reviewed.json current.graph.json` | `matches-evidence`: 0; `changed-since-review`: 1; `cannot-check`: 2. |

All commands exit 2 for invalid usage, unsupported/unreadable input, or unsafe output. Full identities, observations, diagnostics, and limits remain in `--format json`. MCP report commands `compare`, `sign`, and `verify` accept **MCP scan reports**, not graph/review evidence.

A receipt is **caller-declared, unsigned, unauthenticated, and advisory-only**. It does not prove human review, capture authenticity, installation continuity, restoration history, or runtime safety. `review-check` never updates a receipt or promotes changed evidence. Compare a restored capture with the original baseline separately, as above. Graphs report local declarations; runtime discovery, reachability, initialization, permissions in effect, and instruction meaning remain unobserved.

## Package status and compatibility

| Identity | Version / scope |
|---|---|
| Public candidate package and CLI | `0.8.0-rc.1`; archive download, no npm registry publication |
| MCP analyzer | `0.6.3`; established MCP scan IDs preserved |
| Artifact and Codex harness analyzers | `0.7.0`; graph, comparison, and receipt schemas/identities unchanged |
| Prior immutable released package | `0.7.0`; lacks the graph and retained-review commands |

The candidate's complete local workflow is capture → compare → manual review/restoration → recapture → retain → check again. Hosted monitoring, organization policy, a dashboard, and runtime protection are not current capabilities. The source package retains `private: true` to prevent npm registry publication.

[Artifact snapshots](docs/v0.7-artifact-snapshots.md) and [Codex harness / permission delta](docs/v0.7-codex-harness.md) provide the richer separate reports. The [MCP guide](docs/mcp-scanning.md) preserves the rule catalog, immutable archive installation, scan/compare/sign recipes, accuracy policy, and Action overview. Previously published archives remain unchanged; the current source observation template pins the reviewed candidate commit documented in the [Action guide](docs/github-action.md).

## Build a local candidate from source

Source development requires pinned **pnpm 11.19.0**. From a fresh checkout/export, install dependencies and run the required gates. `pnpm pack` builds the CLI and creates the uniquely named archive. Use a new output directory; do not replace a previously reviewed archive. Keep its checksum sidecar beside it, outside the archive.

```sh
pnpm install --frozen-lockfile
pnpm check
pnpm scan:self
```

PowerShell, from that source directory:

```powershell
$pack = Join-Path ([IO.Path]::GetTempPath()) ('uleravo-candidate-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $pack | Out-Null
pnpm pack --pack-destination $pack
if ($LASTEXITCODE -ne 0) { throw 'Packing failed.' }
$archive = Join-Path $pack 'uleravo-0.8.0-rc.1.tgz'
$digest = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$archive.sha256", "$digest  uleravo-0.8.0-rc.1.tgz`n")
$pack
```

Ubuntu / POSIX shell, from that source directory:

```sh
pack="$(mktemp -d "${TMPDIR:-/tmp}/uleravo-candidate.XXXXXX")"
pnpm pack --pack-destination "$pack"
(cd "$pack" && sha256sum uleravo-0.8.0-rc.1.tgz > uleravo-0.8.0-rc.1.tgz.sha256)
printf '%s\n' "$pack"
```

Change to the printed directory and use the installation/checksum verification block above. The digest identifies supplied bytes; a sidecar alone does not authenticate the supplier.

`pnpm check` runs formatting/lint, strict TypeScript, tests with unchanged coverage thresholds, build, byte-for-byte Action bundle verification, exact content-hashed export validation, and the immutable-pin publication check. `scan:self` excludes tests and the exact deliberately vulnerable MCP sample target. The exact disclosure-safe source inventory is `release/public-export.json` in the source checkout. The [architecture](docs/architecture.md), [threat model](docs/threat-model.md), [rule guide](docs/rules.md), [result-reporting guide](docs/reporting-results.md), and [security policy](SECURITY.md) document coverage and reporting boundaries. Passing checks is not a complete security-review claim.

## License and name

The core is licensed [Apache-2.0](LICENSE). Bundled third-party material is documented in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES). Hosted-service code is outside this release surface.

Uleravo is the public-beta name after preliminary exact, near-name, namespace, common-law, package-registry, domain, and multilingual screening. This is launch-stage screening, not formal trademark advice; obtain Saudi and international counsel review before filing or major paid promotion.
