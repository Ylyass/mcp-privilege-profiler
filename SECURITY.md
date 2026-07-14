# Security policy

## Supported versions

Before the first release, only the default branch is supported. Supported
release versions will be listed here after v0.1.0.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Until a private
security contact is configured, report it privately to the repository owner.

Include affected version or commit, reproducible steps, impact, and any
suggested mitigation. Do not include real secrets, production credentials, or
destructive proof-of-concept payloads.

## Security design commitments

- default-deny enforcement;
- no raw arguments or results in default audit events;
- fail-closed behavior for mandatory audit failure;
- reviewed policies linked to tool fingerprints;
- documented limitations and reproducible tests.

