# Security policy

## Supported versions

Before the first release, only the default branch is supported. Supported
release versions will be listed here after v0.1.0.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
**Report a vulnerability** form in the repository Security tab. Public release
is blocked until private vulnerability reporting is enabled and this path has
been tested by the maintainer.

Include affected version or commit, reproducible steps, impact, and any
suggested mitigation. Do not include real secrets, production credentials, or
destructive proof-of-concept payloads.

The project intentionally does not publish a personal email address as its
security channel. A public mailbox is easy to scrape and does not provide the
repository-linked disclosure workflow, access control, or advisory record that
GitHub private vulnerability reporting provides.

## Security design commitments

- default-deny enforcement;
- no raw arguments or results in default audit events;
- fail-closed behavior for mandatory audit failure;
- reviewed policies linked to tool fingerprints;
- finite human-reviewed limits on every non-DENY rule;
- exact, expiring, single-use approval permits without persisted raw arguments;
- documented limitations and reproducible tests.
