# Dependency security and licence review

This record explains how third-party Python packages are controlled before an
open-source release. It is evidence for one review date, not a promise that a
dependency can never receive a later advisory.

## Controls

- `uv.lock` records the exact resolved development and runtime environment.
- Runtime requirements use bounded version ranges in `pyproject.toml`.
- CI verifies the lockfile, installs with `--locked`, and runs `uv pip check`.
- Dependabot is configured to propose Python and GitHub Actions updates.
- Release-candidate review exports the locked runtime graph and scans it with
  PyPA `pip-audit` against the Python Packaging Advisory Database.
- Licence metadata is reviewed for the installed direct and transitive graph.

## Review on 5 August 2026

The first scan of the MCP SDK 2.0.0 runtime graph found one known high-severity
advisory in transitive dependency `cryptography 49.0.0`: CVE-2026-69247 /
GHSA-g6cj-pr64-35w5. The project does not call the affected PKCS#7 decryption
functions, but a security tool should not knowingly retain a vulnerable package.

The runtime floor was therefore raised to `cryptography>=50.0.0,<51`, the lock
was updated to 50.0.0, and the exact 39-package runtime graph was scanned again.
The second scan reported zero known vulnerabilities.

The direct runtime dependencies and their declared licence families are:

| Dependency | Locked version | Declared licence |
|---|---:|---|
| aiosqlite | 0.22.1 | MIT |
| AnyIO | 4.14.2 | MIT |
| cryptography | 50.0.0 | Apache-2.0 OR BSD-3-Clause |
| jsonschema | 4.26.0 | MIT |
| MCP Python SDK | 2.0.0 | MIT |
| Pydantic | 2.13.4 | MIT |
| rfc8785 | 0.1.4 | Apache-2.0 |
| Typer | 0.26.8 | MIT |

The inspected transitive runtime graph declared permissive licences compatible
with this project's Apache-2.0 distribution. Development-only dependencies are
not included in the installed runtime package; Hypothesis is MPL-2.0 and is used
only for tests.

## Release interpretation

An audit result means that the advisory database contained no known match for
the exact package versions at scan time. It does not prove the absence of an
unknown vulnerability. A release still requires hosted Dependabot/CI checks and
normal security review.

The generated audit input and JSON result remain ignored local evidence under
`.mcp-privprof/release-audit/`; they are not published as permanent claims.
