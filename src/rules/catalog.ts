import type { RuleMetadata } from "../domain.js";

export const RULES = {
  commandInjection: {
    confidence: "high",
    description: "Untrusted MCP tool input reaches a shell command interpreter.",
    id: "MCP001",
    remediation:
      "Replace shell execution with a fixed executable and an argument array. Validate each argument against an allowlist and keep shell mode disabled.",
    severity: "critical",
    standards: {
      atlas: [],
      cwe: ["CWE-78"],
      owasp: ["OWASP-LLM06:2025"],
    },
    title: "MCP input reaches shell execution",
  },
  arbitraryExecutable: {
    confidence: "high",
    description: "Untrusted MCP tool input controls the executable launched by the server.",
    id: "MCP002",
    remediation:
      "Use a constant executable path. Map an allowlisted operation name to fixed commands and reject every unknown value.",
    severity: "high",
    standards: {
      atlas: [],
      cwe: ["CWE-78"],
      owasp: ["OWASP-LLM06:2025"],
    },
    title: "MCP input controls an executable",
  },
  pathTraversal: {
    confidence: "medium",
    description:
      "Untrusted MCP tool input is used as a filesystem path without a visible boundary check.",
    id: "MCP003",
    remediation:
      "Resolve the requested path beneath a fixed root, compare the canonical path to that root, and reject absolute paths and parent traversal.",
    severity: "high",
    standards: {
      atlas: [],
      cwe: ["CWE-22"],
      owasp: ["OWASP-LLM06:2025"],
    },
    title: "MCP input reaches a filesystem path",
  },
  serverSideRequestForgery: {
    confidence: "medium",
    description: "Untrusted MCP tool input controls an outbound request URL.",
    id: "MCP004",
    remediation:
      "Parse the URL, require HTTPS, allowlist exact hosts and ports, resolve DNS safely, and block loopback, link-local, and private address ranges.",
    severity: "high",
    standards: {
      atlas: [],
      cwe: ["CWE-918"],
      owasp: ["OWASP-LLM06:2025"],
    },
    title: "MCP input controls an outbound request",
  },
  dynamicCode: {
    confidence: "high",
    description: "Runtime code generation appears inside an MCP request handler.",
    id: "MCP005",
    remediation:
      "Remove runtime code evaluation. Implement the allowed operations directly and dispatch through a closed allowlist.",
    severity: "critical",
    standards: {
      atlas: [],
      cwe: ["CWE-95"],
      owasp: ["OWASP-LLM06:2025"],
    },
    title: "Dynamic code execution in an MCP handler",
  },
  poisonedDescription: {
    confidence: "high",
    description: "A tool description contains instructions associated with tool poisoning.",
    id: "MCP006",
    remediation:
      "Keep tool descriptions factual and user-visible. Remove hidden behavioral instructions and never ask a model to collect or transmit credentials.",
    severity: "high",
    standards: {
      atlas: ["AML.T0051"],
      cwe: ["CWE-94"],
      owasp: ["OWASP-LLM01:2025", "OWASP-LLM03:2025"],
    },
    title: "Suspicious instructions in a tool description",
  },
  hardcodedSecret: {
    confidence: "high",
    description: "A credential-like value is embedded in source or configuration.",
    id: "MCP007",
    remediation:
      "Revoke the exposed credential, remove it from history, and load the replacement from a narrowly scoped secret store at runtime.",
    severity: "high",
    standards: {
      atlas: [],
      cwe: ["CWE-798"],
      owasp: ["OWASP-LLM02:2025"],
    },
    title: "Hardcoded credential",
  },
  insecureTransport: {
    confidence: "high",
    description: "A non-local endpoint uses cleartext HTTP.",
    id: "MCP008",
    remediation:
      "Use HTTPS and validate the remote certificate. Keep cleartext HTTP limited to loopback development endpoints.",
    severity: "medium",
    standards: {
      atlas: [],
      cwe: ["CWE-319"],
      owasp: [],
    },
    title: "Cleartext remote transport",
  },
  credentialInUrl: {
    confidence: "high",
    description: "A URL embeds credentials in userinfo or a sensitive query parameter.",
    id: "MCP009",
    remediation:
      "Remove credentials from the URL. Supply short-lived credentials through an authorization header or secret binding and redact them from logs.",
    severity: "high",
    standards: {
      atlas: [],
      cwe: ["CWE-598"],
      owasp: ["OWASP-LLM02:2025"],
    },
    title: "Credential embedded in a URL",
  },
  unpinnedPackage: {
    confidence: "high",
    description: "An MCP server is executed from a mutable package reference.",
    id: "MCP010",
    remediation:
      "Pin the exact package version and commit the ecosystem lockfile. Update it deliberately through reviewed dependency changes.",
    severity: "medium",
    standards: {
      atlas: [],
      cwe: ["CWE-1357"],
      owasp: ["OWASP-LLM03:2025"],
    },
    title: "Mutable MCP package reference",
  },
  environmentPassthrough: {
    confidence: "high",
    description: "The complete host environment is forwarded to a child MCP process.",
    id: "MCP011",
    remediation:
      "Build a new environment object containing only the variables the child server requires. Never forward process.env wholesale.",
    severity: "medium",
    standards: {
      atlas: [],
      cwe: ["CWE-200"],
      owasp: ["OWASP-LLM02:2025"],
    },
    title: "Host environment forwarded to a child process",
  },
  destructiveAnnotation: {
    confidence: "medium",
    description: "A destructive tool does not advertise its destructive behavior to MCP clients.",
    id: "MCP012",
    remediation:
      "Set annotations.destructiveHint to true and require explicit user confirmation before the operation runs.",
    severity: "low",
    standards: {
      atlas: [],
      cwe: ["CWE-862"],
      owasp: ["OWASP-LLM06:2025"],
    },
    title: "Destructive tool lacks an MCP annotation",
  },
} as const satisfies Record<string, RuleMetadata>;

export const RULE_CATALOG: readonly RuleMetadata[] = Object.values(RULES);
