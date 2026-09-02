# Rule reference

Uleravo v0.6.3 reports twelve focused risk classes in MCP implementations and configuration. The scanner is static: it does not import or execute target code, start an MCP server, make network requests, or prove that a deployed service matches the scanned source.

Each finding includes a default severity and confidence. Severity describes the potential impact of the detected pattern. Confidence describes how strongly the supported static pattern establishes the stated risk. A complete scan means that selected inputs were processed without error diagnostics under the documented coverage; it does not mean that every vulnerability class or program path was analyzed.

| Rule | Risk | Severity | Confidence |
| --- | --- | ---: | ---: |
| `MCP001` | MCP input reaches shell execution | Critical | High |
| `MCP002` | MCP input controls an executable | High | High |
| `MCP003` | MCP input reaches a filesystem path | High | Medium |
| `MCP004` | MCP input controls an outbound request | High | Medium |
| `MCP005` | Dynamic code execution in an MCP handler | Critical | High |
| `MCP006` | Suspicious instructions in a tool description | High | High |
| `MCP007` | Hardcoded credential | High | High |
| `MCP008` | Cleartext remote transport | Medium | High |
| `MCP009` | Credential embedded in a URL | High | High |
| `MCP010` | Mutable MCP package reference | Medium | High |
| `MCP011` | Host environment forwarded to a child process | Medium | High |
| `MCP012` | Destructive tool lacks an MCP annotation | Low | Medium |

The safe patterns below are review aids, not universal proofs of safety. Application-specific validation, authorization, and deployment controls still matter.

## `MCP001`: MCP input reaches shell execution

**Trigger.** Tool-controlled data reaches a recognized shell interpreter. JavaScript and TypeScript coverage includes recognized `child_process` shell APIs and `execFile` or `spawn` calls with literal `shell: true`. Python coverage includes recognized shell APIs and subprocess calls with literal `shell=True`.

**Why it matters.** A caller may be able to add shell syntax and execute commands with the MCP server's operating-system privileges.

**Safe or non-trigger pattern.** Select a fixed executable and pass separately validated arguments in an array with shell mode disabled. For example, `execFile("/usr/bin/git", ["status"], { shell: false })` does not place tool input in a shell command string.

**Remediation.** Replace shell execution with a fixed executable and argument array. Allowlist each supported operation and argument shape, reject unknown values, and keep shell mode disabled.

**Precision limits.** This is a high-confidence finding for the recognized flow. For a recognized process call with literal shell mode enabled, the check covers visible taint in the command or argument vector, not unrelated options such as `cwd` or `env`. JavaScript and TypeScript analysis is primarily intraprocedural and follows only one supported direct named relative import. Python analysis is primarily intraprocedural. Custom registration wrappers, unsupported process libraries, multi-hop helpers, and dynamically resolved calls may be missed. A fixed executable also needs argument validation because dangerous target-program options are outside this rule's shell-injection decision.

## `MCP002`: MCP input controls an executable

**Trigger.** Tool-controlled data selects the executable passed to a recognized `spawn`, `execFile`, or Python subprocess operation, including a Python `executable` override.

**Why it matters.** A caller may choose an unintended binary or script and run it with the server's privileges even when no shell parses the command.

**Safe or non-trigger pattern.** Map a small, allowlisted operation name to fixed executable paths. Keep the executable constant and pass validated data only in the argument positions intended by that program.

**Remediation.** Use a constant executable path, define a closed mapping from supported operations to commands, and reject every unknown operation.

**Precision limits.** This is a high-confidence finding for supported process APIs and visible data flow. Indirect wrappers, dynamically selected libraries, multi-hop flow, and dangerous option injection into an otherwise fixed executable may fall outside this rule.

## `MCP003`: MCP input reaches a filesystem path

**Trigger.** Tool-controlled data reaches a recognized filesystem path position without a guard the analyzer can see. Supported JavaScript and TypeScript sinks include common `node:fs` operations and inspect both source and destination for `rename`; Python coverage includes common built-in, `os`, and `pathlib` operations.

**Why it matters.** A caller may read, create, overwrite, rename, or remove files outside the directory intended by the tool.

**Safe or non-trigger pattern.** The current analyzer recognizes direct `basename`-style narrowing and preserves that state through selected assignments, joins, and one supported JavaScript or TypeScript import edge. This is only an analyzer-recognized pattern, not a complete filesystem boundary: symlinks, aliases, and operation-specific behavior still require review.

**Remediation.** Resolve the requested path beneath a fixed root, reject absolute paths and parent traversal, canonicalize the relevant existing path or ancestor, and verify containment before access. Use an operation-specific allowlist when the tool needs only named files.

**Precision limits.** This rule is medium-confidence because a valid custom containment check may be outside the analyzer's narrow guard model. Conversely, `basename` alone does not prove that every filesystem race or symlink case is safe. Interprocedural validators, custom filesystem wrappers, unsupported sinks, and path positions not explicitly modeled for a supported sink may be missed.

## `MCP004`: MCP input controls an outbound request

**Trigger.** Tool-controlled data reaches the URL argument of a recognized outbound-request API without a destination boundary the analyzer can establish. Python formatted URLs with a literal HTTP or HTTPS authority and only a variable path are treated as having a fixed destination.

**Why it matters.** A caller may make the server contact internal services, cloud metadata endpoints, loopback services, or attacker-controlled destinations.

**Safe or non-trigger pattern.** Construct requests from a fixed HTTPS origin and allowlisted operation paths. Parse any user-supplied URL and require an exact approved scheme, hostname, and port before resolving and connecting. Python recognizes a formatted string whose literal prefix fixes the complete authority; JavaScript and TypeScript may still report a safe fixed-origin construction for manual review.

**Remediation.** Require HTTPS, allowlist exact hosts and ports, resolve DNS safely, and reject loopback, link-local, private, and otherwise prohibited address ranges at the connection boundary.

**Precision limits.** This rule is medium-confidence because a custom destination validator may not be visible to the analyzer. JavaScript and TypeScript currently do not model arbitrary host allowlists. Unsupported HTTP clients, helper graphs, redirects, proxy behavior, DNS rebinding, and checks performed outside the supported flow may be missed or require manual review.

## `MCP005`: Dynamic code execution in an MCP handler

**Trigger.** JavaScript or TypeScript uses `eval` or constructs `Function` within a recognized MCP handler. Python passes tool-controlled data to a recognized `eval` or `exec` function.

**Why it matters.** Dynamically evaluated input can become code running with the MCP server's privileges and access.

**Safe or non-trigger pattern.** Represent supported behavior as data and dispatch through a closed mapping to ordinary functions. Parse a narrow input grammar when expressions are required instead of evaluating source text.

**Remediation.** Remove runtime code evaluation and implement allowed operations directly behind an allowlist.

**Precision limits.** This is a high-confidence finding for recognized syntax. The JavaScript and TypeScript rule reports the dynamic-code construct inside a handler even when its argument is not visibly tainted; Python requires visible tool-input flow. Custom evaluators, template engines, virtual machines, unsupported wrappers, and multi-hop flow may be outside coverage.

## `MCP006`: Suspicious instructions in a tool description

**Trigger.** A literal description supplied to a recognized `tool` or `registerTool` call matches a focused pattern for overriding higher-priority instructions, secretly influencing the model, or collecting and transmitting credentials.

**Why it matters.** MCP tool metadata is model-visible. Behavioral instructions hidden in a description can redirect an agent, conceal activity from the user, or solicit sensitive data.

**Safe or non-trigger pattern.** Keep descriptions factual, concise, and user-visible: state what the tool does, its important effects, and the input meaning without instructing the model to ignore policy, hide behavior, or collect secrets.

**Remediation.** Remove behavioral or concealed instructions. Put legitimate workflow requirements in explicit application policy and never ask the model to retrieve or transmit credentials.

**Precision limits.** This is high-confidence for the narrow matched phrases, not a semantic judgment of every description. The rule currently checks literal descriptions on recognized JavaScript and TypeScript registrations. Dynamically assembled text, wrappers, other languages, paraphrases, and non-English instructions may be missed; legitimate security documentation containing a matched phrase may require review.

## `MCP007`: Hardcoded credential

**Trigger.** A private-key block, a supported provider-secret shape, or a sufficiently credential-like assigned value is embedded in a scanned source or configuration file. Generic unquoted assignment detection is limited to environment, YAML, and TOML files; generic values in other files must be quoted.

**Why it matters.** A committed credential can be copied from source, reports, artifacts, caches, or repository history and used outside the intended process.

**Safe or non-trigger pattern.** Load the value at runtime from a narrowly scoped environment binding or secret manager. Generic credential candidates containing markers such as `fake`, `test`, `example`, `placeholder`, or `redacted` are suppressed by the current content heuristic. Known provider-shaped values use a much narrower test/example check that accepts only exact documented provider examples or unmistakable repeated or sequential fixture filler.

**Remediation.** Revoke the exposed credential, remove it from repository history and artifacts where feasible, create a narrowly scoped replacement, and load it from a secret binding.

**Precision limits.** This is high-confidence for known secret shapes and strong generic assignment patterns. The broad placeholder heuristic can suppress a live generic credential containing one of its synthetic markers; provider-shaped values are exempt from that heuristic and remain reportable in recognized fixtures unless they match a reviewed provider example or use unmistakable filler. Unknown provider formats, short or low-entropy credentials, encoded or fragmented values, runtime construction, and secrets fetched through unsupported formats may also be missed. High-entropy non-secret identifiers can resemble generic credentials and should be reviewed. Finding evidence is redacted, but the original source and repository history still require incident handling.

## `MCP008`: Cleartext remote transport

**Trigger.** A parseable literal URL uses `http://` with a non-local hostname. Loopback development hosts and a small set of standard non-transport identifiers are excluded.

**Why it matters.** Cleartext remote traffic can expose requests, responses, credentials, or tool data to interception and modification.

**Safe or non-trigger pattern.** Use `https://` and validate the remote certificate. Plain HTTP limited to loopback development endpoints such as `127.0.0.1` or `localhost` is not reported by this rule.

**Remediation.** Move the endpoint to HTTPS with certificate validation. Keep any cleartext listener local and prevent it from becoming remotely reachable through deployment configuration.

**Precision limits.** This is high-confidence for literal remote HTTP URLs. Recognized test files are skipped. The rule does not establish certificate quality, redirect safety, proxy behavior, or whether a local endpoint is exposed externally. Constructed URLs, formatted authorities, alternate protocols, and endpoints that appear only at runtime may be outside literal-URL coverage.

## `MCP009`: Credential embedded in a URL

**Trigger.** A parseable literal HTTP or HTTPS URL contains username/password userinfo or a recognized sensitive query key such as `token`, `api_key`, `password`, or `secret`.

**Why it matters.** URLs commonly appear in logs, browser and proxy history, monitoring data, referrer metadata, shell history, and error messages.

**Safe or non-trigger pattern.** Keep credentials out of the URL. Bind a short-lived secret at runtime and send it through an authorization header or another protocol-appropriate secret field that is excluded from logs.

**Remediation.** Remove and rotate any exposed credential, replace it with a narrowly scoped short-lived value, and redact credential-bearing metadata from existing logs and artifacts where possible.

**Precision limits.** This is high-confidence for supported URL syntax and sensitive key names. Custom parameter names, path or fragment secrets, constructed URLs, non-HTTP schemes, and credentials added after parsing may be missed. Uleravo redacts recognized values from finding evidence, but the source value must still be treated as exposed.

## `MCP010`: Mutable MCP package reference

**Trigger.** An MCP-looking dependency in `package.json` uses a mutable version without an applicable lockfile, or an `mcpServers` JSON entry launches a non-exact package reference through `npx`, `pnpx`, `bunx`, or `uvx`.

**Why it matters.** The same configuration can resolve to different code over time, allowing an unreviewed update or upstream compromise to change what the agent executes.

**Safe or non-trigger pattern.** Use an exact package version or immutable 40-character commit reference and commit the relevant ecosystem lockfile. In an MCP client configuration, put the exact version directly in the package-runner argument, such as `package@1.2.3` for JavaScript package runners or `package==1.2.3` for `uvx`.

**Remediation.** Pin the exact package version, commit and review the lockfile, and update both deliberately through a dependency-review process.

**Precision limits.** This is high-confidence for supported JSON shapes, package runners, and names recognized as MCP-related. A lockfile covers a `package.json` only when it is in the same directory or an ancestor; a sibling lockfile does not count. Lockfiles establish resolution state, not publisher trust or package integrity. Other manifests, launchers, registries, package aliases, and packages whose names do not identify them as MCP-related may be missed.

## `MCP011`: Host environment forwarded to a child process

**Trigger.** A JavaScript or TypeScript child-process launch or `StdioClientTransport` options object forwards `process.env` as the `env` value or includes it as a whole through a visible construction such as object spread. Selecting an individual property such as `process.env.PATH` does not trigger this rule.

**Why it matters.** The child receives every credential and sensitive configuration variable available to the parent, even when it needs only a few non-secret values.

**Safe or non-trigger pattern.** Build a separate environment object containing only explicitly named variables required by the child, validate those values, and pass that object as `env`. Review whether each forwarded value is necessary.

**Remediation.** Replace wholesale environment forwarding with a narrow allowlist, use scoped secret bindings for values the child legitimately needs, and remove unrelated credentials from the parent process where possible.

**Precision limits.** This is high-confidence for direct whole-environment references. Aliased environment objects, helper-built options, custom transports, Python process launches, and other indirect propagation may be missed. The rule does not decide whether individually selected variables are overprivileged.

## `MCP012`: Destructive tool lacks an MCP annotation

**Trigger.** A literal JavaScript or TypeScript tool name equals a recognized destructive verb such as `delete`, `destroy`, `drop`, `remove`, `revoke`, or `wipe`, or starts with that verb followed by `_`, `-`, or a camel-case boundary, and the recognized registration does not contain literal `annotations.destructiveHint: true`.

**Why it matters.** An MCP client may not warn the user or apply an appropriate confirmation policy when the tool can cause irreversible or difficult-to-recover effects.

**Safe or non-trigger pattern.** Declare `annotations: { destructiveHint: true }` in the tool metadata and enforce explicit confirmation and authorization in the application before performing the operation.

**Remediation.** Add the annotation, require confirmation for the exact operation and target, enforce authorization server-side, and make recovery or rollback guidance available where practical.

**Precision limits.** This is a medium-confidence naming and metadata heuristic. The scanner recognizes a focused verb prefix list with explicit separators or camel-case boundaries, literal names, and supported JavaScript or TypeScript registrations; concatenated lowercase names, synonyms, dynamic names, wrappers, and other languages may be missed. A declared hint does not prove that confirmation, authorization, or rollback is implemented, and a matched name may describe a non-destructive dry run.

## Shared analysis boundary

JavaScript and TypeScript analysis recognizes documented MCP handler registrations and is primarily intraprocedural. It follows exactly one module edge when a handler directly calls a top-level exported function from a static named relative ESM import. Default, namespace, CommonJS, dynamic, and package imports; re-exports; path aliases; return flow; arbitrary helper graphs; and second-hop calls are outside that boundary.

Python analysis recognizes handlers connected to supported top-level FastMCP or MCP Server imports and common direct decorators. It is primarily intraprocedural. Local imports, custom registration wrappers, and general interprocedural flow are outside the current boundary.

Recognized JavaScript and TypeScript test files are skipped by the handler and tool-metadata analysis that produces `MCP001` through `MCP006`, `MCP011`, and `MCP012`. Recognized Python test files are skipped by the Python handler analysis. Literal and configuration rules have their own documented boundaries; a complete scan does not imply that intentionally skipped test code was analyzed by those handler rules.

Uleravo v0.6.x has no source suppression format. Do not hide a disputed finding with a broad scan exclusion. Review it, record the risk decision outside the source, and submit a sanitized correction report using [Reporting results and corrections](reporting-results.md).
