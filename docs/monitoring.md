# Read-only configuration posture monitoring

`uleravo monitor` observes configuration declarations. It does not launch, proxy, pause, or block an agent; run MCP commands, shells, hooks or credential helpers; read prompts or tool arguments from a running agent; or determine effective permissions. Findings are review suggestions, not proof of exploitation or runtime enforcement.

## Runtime support

Current source supports the verified LTS ranges `^22.23.2 || ^24.19.0`. CI is configured to run the same full checks on Windows and Linux at Node 22.23.2 and 24.19.0. These are selected verified baselines, **not the earliest fixed releases**.

An actual Windows Node 22.13.0 investigation found conflicting pathname/handle device IDs for the same unchanged file. Its bundled libuv reads the native Windows metadata structure incorrectly; changing to BigInt does not recover the missing device identity. The reader deliberately retains strict device, inode, size, timestamp and path checks. Earlier or other undeclared runtimes are not covered by this source support policy; use a supported runtime rather than bypassing a failed identity check.

This does not change a published archive's bytes or retroactively certify an old runtime. The current source's stricter runtime metadata and the unchanged older archives are separate artifacts. The underlying fixes are [libuv's structure-layout correction](https://github.com/libuv/libuv/commit/abe59d6319973cbff0686f41869cf8ae50bab1d2) and [consistent volume serial handling](https://github.com/libuv/libuv/commit/82cdfb75ff9bbd0dc65820ca418b7c5d412ff4d7).

## Quick project check (unreleased)

`check` is a development addition; it is **not in the unchanged `0.8.0-rc.1` or `0.9.0-rc.2` archives**. With a build containing it installed, start in your project:

```bash
uleravo check
# Or select a different existing project (quote Windows paths):
uleravo check "C:/work/my-project"
# Inspect the reported file/field, make a reviewed manual edit, then repeat.
uleravo check "C:/work/my-project"
```

For a local npm install use `./node_modules/.bin/uleravo` (`./node_modules/.bin/uleravo.cmd` in Windows PowerShell) if the command is not on PATH. `uleravo check --help` confirms support in that installed build. No account, hash copying or saved evidence pair is needed.

This single fresh capture uses the same bounded monitoring parser, filtering, identities and safe local-observation locators as `monitor --explain`. It prints plain titles, local review severity (HIGH before MEDIUM), relative file/selector, why and manual guidance for all current findings. Local presentation metadata is separate from the unchanged monitoring wire schema and is never upload telemetry. It does not print configuration values, labels, commands, URLs, credential names, absolute target paths or hash identifiers.

The header lists **actually read harness/project groups**, not every candidate filename: Claude coverage aggregates its three supported project files and can include missing optional files. Cursor and Codex each have one supported project file. Missing/error groups are stated explicitly; a group read is not full provider-schema validation or effective configuration. Existing empty objects or unrelated fields can yield no supported findings; this is not proof that useful declarations or all settings were inspected. The file table below specifies the bounded candidates. No parent-directory configuration discovery, user-home resolution, user-wide read, Skill/source inspection, credential lookup, application network request, watch, target execution or edit occurs. Ancestor filesystem metadata is still inspected by the bounded reader. `check` has no user-wide option; the existing `monitor --include-user` remains a separate explicit-consent workflow.

**Local-target syntax policy (`check` only):** use ordinary relative paths or native absolute paths to a stable project on local storage (for example `./project`, `/work/project` on POSIX, or `C:/work/project` on Windows). Before target filesystem I/O, including `lstat`, both the supplied target and current directory are checked lexically—even an absolute target is refused when the current directory uses unsupported syntax. Empty/control/format-character paths, any leading backslash, two leading separators in any slash/backslash combination, slash-prefixed `??`, `Device`, `GLOBAL??` or `DosDevices` namespaces, and colon-prefixed forms other than a drive letter followed by a separator are unsupported. This rejects explicit UNC paths, Windows device/extended namespace paths (including extended local-drive paths), drive-relative forms such as `C:project`, and URI targets. Paths are not probed to decide whether one of these forms happens to be local.

**Storage limitation:** lexical checks do not identify mapped network drives, mounted network filesystems, or network redirection through ancestors. Ordinary-looking paths and even metadata operations may cause OS filesystem traffic. The existing ancestor/link checks are not atomic against hostile replacement and do not enumerate every reparse mechanism. No application network request is made by `check`, but a no-network expectation requires genuinely local storage, including the executable/dependencies, cwd, target and ancestors; use OS-level restrictions when network isolation is required. JavaScript API guards in tests are selected-API regression tripwires, not OS network isolation. The existing `monitor` target policy is unchanged.

**Additive `check` exit contract:** 0 = complete capture with at least one covered group and no supported findings; 1 = complete covered capture with findings; 2 = invalid arguments/target, no coverage, or incomplete capture. Other commands retain their exits. Finding status is based on the authoritative snapshot, not the number of rendered locators: zero or partial local observations produce an explicit incomplete-presentation warning and still exit 1 when the complete, covered snapshot has findings. An incomplete capture remains exit 2 with all locations withheld. Nonexistent and non-directory targets receive specific guidance. Empty/Skill-only directories are no coverage, not a successful security check. Any malformed/unreadable/unsafe/over-limit group withholds every local finding location, as explanation does; the existing aggregate collector cannot name the exact failing file within a Claude group, so the report lists its candidates rather than guessing.

Rechecking after a reviewed manual edit reports only the fresh observation. No baseline is stored and no past finding is declared resolved. No-findings output expressly is **not verification of security or resolution**. This is declaration review, **not runtime protection, an isolation boundary, or the pending product-integration decision**.

## Local first

```bash
uleravo monitor --project /absolute/path/to/project
uleravo monitor --project /absolute/path/to/project --once
uleravo monitor --project /absolute/path/to/project --watch --interval 30
uleravo monitor --help
```

Use a quoted Windows path when appropriate, for example `--project "C:/work/my-project"`. The project must be explicit and exist. The collector does not infer the repository root, walk parent repositories, inspect source files, or discover arbitrary configuration paths.

Defaults: one capture, **no upload**, project configuration only. Each capture prints one compact v1 JSON object to stdout. Watch output is newline-delimited JSON. Diagnostics and coverage limitations go to stderr. Missing optional configuration files are not errors; no files read means **no coverage**, not a secure project.

`--watch` runs in the foreground. `--interval` is an integer from 30 through 86400 seconds; default 300. The interval is a delay after a capture and its upload attempts finish, so slow reads/uploads do not overlap or cause catch-up bursts. `--once` and `--watch` cannot be combined. Ctrl+C/SIGTERM stops watch; the current bounded upload may take up to ten seconds to finish. No daemon, scheduled task, startup item, disk queue, or background service is installed.

## Precise local review of a subject (opt-in, not telemetry)

No account, endpoint or token is needed for local capture or explanation.

```bash
# SUBJECT_ID is findings[].subjectId from local JSON, or finding.subjectId from the cloud:
uleravo monitor --project /absolute/path/to/project --explain "$SUBJECT_ID"
# Only if the original subject was in user-wide configuration:
uleravo monitor --project /absolute/path/to/project --explain "$SUBJECT_ID" --include-user
```

`--explain` accepts exactly **64 lowercase hexadecimal characters**. Copy `finding.subjectId`, not the finding's `id`; both look like hashes but identify different things. It uses the same fresh bounded reads, parser, declaration filtering and subject identity calculation as normal capture. There is no cached location index, second parser, secret lookup, cloud query, target execution or edit operation. Use the original local project location; relocation can change subject identity.

This explicitly selected mode replaces wire JSON stdout with a **LOCAL-ONLY explanation (not telemetry)**. It prints the fixed project-relative (or, for `user`, home-relative) supported configuration filename, a safe declaration selector and static advice for each currently observed rule on that subject. It never prints an absolute project/home path, server label, credential field name, secret/configuration value, launcher command, argument or URL. Even labels that contain secrets, terminal escapes, bidirectional controls or URL text are withheld rather than escaped and reproduced. Do not feed this human review report to ingestion; ordinary captures and upload envelopes remain unchanged.

Selectors:

- Permissions use JSON pointers `/permissions/defaultMode` or `/permissions/allow`; a single permissions subject may have both rules. Codex's fixed selector `sandbox_mode` is a top-level TOML key.
- Server subjects use `mcpServers entry #N` (JSON) or `mcp_servers entry #N` (TOML), **one-based parsed key order**, including disabled entries when counting. This identifies the parsed declaration without revealing its label. Integer-index keys enumerate first in numeric order; other keys retain the parser's insertion order. This is not finding order, alphabetical order or a source line number. Reordering the file can change the printed ordinal, so the report always reads again. Consult the named container locally; never execute its contents to locate it.
- A settings-wide credential subject uses `JSON Pointer ""` (the settings root), identifying the same declaration scope as the finding. Review its inspected credential fields locally; field names and values are not printed.

`--explain` **cannot be combined with `--upload` or `--watch`**. These combinations and malformed IDs fail before filesystem capture, user-home resolution, credential resolution or network work. An endpoint or token-variable-name option alone does not cause credentials to be read or a request to be sent. User-wide collection still requires `--include-user`.

Any incomplete fresh capture (including a malformed, unsafe, linked, oversized or over-limit configuration anywhere in the requested coverage) exits **2 and withholds every location**, even a match in another readable group. A complete capture with no current match exits 0 and explicitly says **Subject not observed**, **not verification of security or resolution**. Removed/renamed declarations, filtered disabled entries, changed posture, a different project location, an omitted user scope or the wrong identifier can all cause non-observation. Do not interpret this as a resolved finding.

Advice is manual review guidance, not a generated patch or a security decision. After making a reviewed change yourself, run a fresh normal capture and compare the observations; retain the review decision separately. The explanation does not update cloud findings or prove effective runtime permissions.

## Explicit upload opt-in

Create a revocable device token in your Uleravo account **for each monitored project** and provide it through an environment variable. One token monitors one explicit project, even when several projects share a computer. Prefer setting it through your shell's secure credential workflow, rather than putting a literal token in shell history.

```bash
# ULERAVO_TOKEN must already be set in this process environment.
uleravo monitor --project /absolute/path/to/project \
  --watch --interval 300 --upload \
  --endpoint https://YOUR-ULERAVO-HOST/api/ingest

# This token belongs ONLY to project-a; set it securely in the environment.
# The argument is a VARIABLE NAME, not a token.
uleravo monitor --project /absolute/path/to/project-a --upload \
  --endpoint https://YOUR-ULERAVO-HOST/api/ingest \
  --token-env ULERAVO_PROJECT_A_TOKEN
```

**`--endpoint` is the full ingestion URL, including `/api/ingest`. The collector does not append that path.** There is no default hosted destination. `--upload` requires an endpoint and a nonempty valid bearer token in the selected environment variable. The default variable is `ULERAVO_TOKEN`. There is no `--token` argument, credential file fallback, login command, or implicit network upload. Supplying an endpoint without `--upload` still does not send anything.

Endpoints must be HTTPS, except HTTP on `localhost`, IPv4 loopback `127.0.0.0/8`, or IPv6 `[::1]`. Userinfo, query strings, fragments, and control characters are rejected. Redirects are never followed, including same-origin redirects. The token is sent only in `Authorization: Bearer ...`, never in the JSON body, URL, or diagnostics. Only send to an ingestion service you trust.

Each attempt has a ten-second timeout including the response body. Acknowledgments are bounded to 8 KiB and must contain `accepted: true`, boolean `duplicate`, and a nonnegative integer `openFindings`. A 2xx response alone is not success. Failure messages omit server response bodies and exception details.

Once mode attempts upload once. Watch mode attempts a failed upload at most three times per capture, waiting one second and then two seconds between retries. Retries reuse the exact capture ID and body for backend idempotency. After exhausted retries, watch reports failure, waits the normal interval, and collects a **new** snapshot; it does not persist or replay an unbounded backlog. Authentication failures are also reported and bounded by that policy: stop watch and replace/revoke the token as appropriate.

Exit status is 0 for a complete capture even when it contains high-severity findings, and 2 for invalid usage, an incomplete capture, or failed upload. Watch returns the latest capture/attempt outcome when stopped. These exit codes concern the collector only; no agent process is controlled.

## Files inspected

Claude Code documents separate project/local settings and MCP configuration locations; project-local MCP state in the home-wide `.claude.json` is different from project-local settings.[1][2]
Codex stores project and user declarations in TOML and documents explicit MCP enable flags and environment credential references.[3]
Cursor documents project and global `mcp.json` files and its own interpolation syntax.[4]

| Harness | Project files | Additional files with `--include-user` |
| --- | --- | --- |
| Claude Code | `.mcp.json`, `.claude/settings.json`, `.claude/settings.local.json` | `~/.claude.json` top-level `mcpServers`; `~/.claude/settings.json` |
| Cursor | `.cursor/mcp.json` | `~/.cursor/mcp.json` |
| Codex | `.codex/config.toml` | `~/.codex/config.toml` |

The default run does not even resolve the user home for collection. `--include-user` is required before reading the listed user-wide files. Their contents are parsed in memory and never uploaded as text. Only the two documented Claude project settings filenames are inspected, not an arbitrary `settings*.json` glob. JSON is strict JSON; TOML is parsed with the installed `smol-toml` parser, not regular expressions or shell evaluation.

User-wide path overrides (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`), managed/registry policy, profile selection, worktree remapping, ancestor configuration layers, command-line overrides, Claude `.claude.json` per-project state, plugins, cloud connectors, Cursor extension registrations and UI enable-state, Codex requirements/profiles, environment files and credential stores are **unobserved**. If your agent uses such layers or nondefault user paths, the default files here must not be mistaken for the files actually used. Scopes are not merged into effective settings, and project trust is not inferred.

`enabled: false` or `disabled: true` MCP entries are omitted from findings/server counts. Claude project entries named in `disabledMcpjsonServers` in the inspected project settings are omitted too. This is declaration filtering, not a determination of runtime enablement or cross-scope precedence. `serverCount` means declarations not explicitly disabled in the inspected source/scope, not running or connected servers.

## Rules

| ID | Declared condition | Review suggestion |
| --- | --- | --- |
| CFG001 | Claude settings `permissions.defaultMode=bypassPermissions` | Confirm external isolation; otherwise use default permissions and scoped allow rules. |
| CFG002 | Codex top-level `sandbox_mode=danger-full-access` | Confirm isolation; otherwise prefer workspace-write/read-only and scoped access. |
| CFG003 | Direct `npx`/`uvx` launcher lacks a recognized exact package version | Pin a reviewed version. A pin does not prove installed artifact identity or transitive dependency integrity. |
| CFG004 | Non-loopback MCP URL uses HTTP | Use HTTPS. Loopback HTTP is excluded from this rule. |
| CFG005 | Literal credential detected in inspected env/header/token/static OAuth-secret fields | Use harness-supported references or credential storage; rotate exposed values. |
| CFG006 | Claude allow list includes `Bash`, `Bash(*)`, or `Bash(:*)` | Scope automatically approved commands; allow rules are not an OS isolation boundary. |

The current Claude settings documentation notes that `bypassPermissions` is ignored in project/local settings in newer versions. CFG001 deliberately reports the **declaration**, not whether that version honors it.[1]

CFG003 recognizes direct launcher executable names (including Windows `.cmd`/`.exe`), basic npm exact semver, Python exact `==` versions, npm `-p`/`--package`, and uvx `--from`. Positional uvx exact shorthand such as `uvx ruff@0.3.0` is recognized; `--from` uses requirement syntax such as `uvx --from 'ruff==0.3.0' ruff`. `@latest`, ranges, and unrecognized options remain reviewable.[5] Wrapped shell commands, interpreter indirection, custom executables, package resolution, and artifact identity are not inspected.

CFG005 is a heuristic over credential-like env/header keys, authorization prefixes, known token fields, and static OAuth secrets, not universal secret detection. Normal environment values are not automatically credentials. Claude `${NAME}` and Cursor `${env:NAME}` references are recognized only as complete references (optionally after `Bearer`/`Basic`); literal fallback defaults or appended literal text remain findings. Codex nested `oauth.client_secret` is a literal credential; `oauth.client_secret_env_var`, `bearer_token_env_var`, `env_http_headers`, and `env_vars` are names, not resolved secret values.[2][3][4] No referenced environment variable is resolved for MCP inspection. Unknown fields, arbitrary source strings, and credentials hidden outside inspected fields remain unobserved.

## Wire/privacy contract

The JSON is the strict, unreleased snapshot v1 envelope: `schemaVersion`, `projectId`, fresh UUID `captureId`, UTC `capturedAt`, `complete`, `configurations`, and `findings`. Configurations aggregate known files by harness and scope: three records by default, six with user opt-in. Each record has `harness`, `scope`, `status` (`read`, `missing`, `error`), `serverCount`, and a SHA-256 `digest` only when read. Findings contain only `id`, `ruleId`, `harness`, `scope`, and `subjectId`.

`projectId` is lowercase SHA-256 of the JSON-encoded canonical local project path (case-normalized on Windows). Only that digest is uploaded, never the path. It does not hash configuration contents, credential values, or remote URLs. The first accepted identity-bearing upload atomically binds the device token to that project; a different project ID returns HTTP 409 `project_conflict` before any capture, freshness, or finding mutation. Renaming/relocating the checkout changes its identity: use a new project token rather than silently replacing the old project's observations. This prevents accidental project switching; it is not attestation against a dishonest token holder.

Compatibility is deliberately fail-safe: `projectId` may be **absent**, but an empty, malformed, or raw-path value is rejected. The collector omits it only when the explicit project root cannot be safely canonicalized, keeping that capture visibly incomplete. Older identity-less captures are accepted for freshness and findings, but the service always stores `lastCaptureComplete: false` and never resolves anything from them, even if they claim `complete: true`. They do not bind or change the token's project. Legacy findings with unknown project provenance cannot be resolved by a subsequent clean identified capture either: they need an identified reobservation first, followed by a complete same-project fix, or explicit review/dismissal. No legacy absence is resolved proof. The additive `0003_collector_identity.sql` migration belongs only to the dedicated monitoring database and must be applied explicitly with the service release.

Subjects are SHA-256 identifiers derived from harness, scope, resolved configuration location and declaration identity (such as a server name or fixed permissions subject). Finding IDs hash the rule, harness, scope and subject ID. IDs remain stable across repeated captures and credential rotation at the same location; relocating a project can change IDs. User findings do not depend on which project was selected. No credential value or credential field name is part of finding identity.

The configuration digest hashes **sanitized posture classifications, file states, counts and finding IDs**, not raw configuration bytes or secret values. Therefore unrelated config edits, URL changes that retain the same posture class, and rotations of a still-literal credential do not necessarily change the digest. This is posture/change monitoring, not a complete file-integrity monitor. Hashes are pseudonymous identifiers, not encryption or a guarantee against guessing low-entropy identities.

The collector constructs the wire data from fixed fields: no source/config text, commands, raw server names, URLs, header/env key names, secret values, home paths, prompts, hooks, or tool arguments are serialized. Default local JSON uses the same secret-free structure as upload. The separate opt-in `--explain` human report is not telemetry: its relative filenames and safe selectors remain in memory and local stdout only, never in a snapshot or upload envelope. Hosted titles, severity and remediation are controlled by the service's rule catalog rather than client-supplied text; local explanation advice is static collector-owned text.

## Safety bounds and completeness

- Reads only regular files; checks every ancestor from the filesystem root with `lstat`, rejects symbolic links/junctions and canonical-path mismatches, and uses `O_NOFOLLOW` where supported.
- Bounded file reads: at most 256 KiB per file plus one sentinel byte. Rejects invalid UTF-8, malformed JSON/TOML and malformed inspected field shapes. It is not a complete validator for every harness setting.
- Checks file identity/size/timestamps before and after reading, and rechecks ancestors/leaf after reading. Stable linked prefixes and tested mutation races fail closed.
- Missing optional files are `missing`; unsafe, malformed, oversized, unreadable files and missing/unsafe explicit roots cause `error` and `complete: false`. Errors are visible in the JSON and stderr without exposing the file's contents or path.
- At most 500 server entries per source, 500 findings per capture, and 128 KiB per encoded snapshot. Excess server entries fail the source. Excess findings/body size mark read coverage as error and omit its findings, never a silently complete truncation.
- Findings are emitted only for harness/scope groups with fully read coverage. A partly malformed Claude group keeps its error status and omits that group's findings, even when another file was readable; findings from other fully read groups can still be included. Incomplete captures reach the ingestion service, update freshness/incomplete state, and never resolve old findings. No coverage and no findings are different statements.

Path-based Node filesystem checks cannot atomically prevent a hostile concurrent ancestor replacement. Native Windows reparse tags beyond links/junctions exposed by Node are not exhaustively enumerated. DOS short-path aliases or unsupported canonical remapping may be rejected conservatively. Hardlinks and hostile same-identity/timestamp-preserving mutation are not an isolation boundary. Use a stable local checkout; no guarantee is made about stalled network filesystems or an adversarial operating system.

## Verification

The collector suite uses temporary fixtures only, including actual Windows junctions, controlled filesystem races, actual loopback HTTP requests, response-body timeout tests, and accelerated watch scheduling with real recapture. It never reads real user configuration or launches fixture commands/hooks.

```bash
node node_modules/vitest/vitest.mjs run test/monitor.test.ts test/monitor-read.test.ts test/monitor-upload.test.ts test/monitor-watch.test.ts
node node_modules/typescript/bin/tsc -p tsconfig.json
```

The transport tests are local contract tests, not evidence of production authentication, billing, agent-runtime visibility, or a paid-launch readiness decision. Parent integration owns CLI dispatch, publishing/packaging, and service-level end-to-end verification.

## Sources

[1] https://code.claude.com/docs/en/settings.md
[2] https://code.claude.com/docs/en/mcp.md
[3] https://developers.openai.com/codex/mcp.md
[4] https://cursor.com/docs/mcp.md
[5] https://docs.astral.sh/uv/guides/tools/#requesting-specific-versions
