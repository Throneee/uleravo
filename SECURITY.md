# Security policy

Please do not open a public issue for a vulnerability that could expose scanner users, their source, or their credentials. Use **Report a vulnerability** on this repository's Security tab to open a private GitHub security advisory and include:

- Affected version and platform
- Minimal reproduction
- Security impact
- Any evidence that the issue is being exploited

The project owner will acknowledge a complete report within five business days. During the observation beta, security fixes target the latest tagged v0.6.x release; older beta builds may be asked to update before a report is reproduced. Before the first tag, report against the exact commit SHA you tested.

Scanner output is a sensitive artifact even though known credential shapes are redacted. Do not attach private source, credentials, customer reports, or full evidence artifacts to a public issue. A detector correction that has no security impact can follow the [sanitized result-reporting guide](docs/reporting-results.md).
