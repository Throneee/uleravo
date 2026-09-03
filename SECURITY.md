# Security policy

Please do not open a public issue for a vulnerability that could expose scanner users, their source, or their credentials. Use **Report a vulnerability** on this repository's Security tab to open a private GitHub security advisory. If private vulnerability reporting is unavailable, email [s.aloufi01@gmail.com](mailto:s.aloufi01@gmail.com) with the subject `Uleravo security report`. Include:

- Affected version and platform
- Minimal reproduction
- Security impact
- Any evidence that the issue is being exploited

Begin with a minimal synthetic reproduction and redacted impact summary. Do not email credentials, customer data, private source, or a complete scanner report; the maintainer can arrange a safer transfer method if additional sensitive evidence is necessary.

The project owner will acknowledge a complete report within five business days. Security fixes target the latest tagged v0.7.x release and the latest v0.6.x compatibility release; older beta builds may be asked to update before a report is reproduced. For an untagged build, report the exact commit SHA you tested.

Scanner output is a sensitive artifact even though known credential shapes are redacted. Do not attach private source, credentials, customer reports, or full evidence artifacts to a public issue. A detector correction that has no security impact can follow the [sanitized result-reporting guide](docs/reporting-results.md).
