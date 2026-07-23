# Release and open-source publication process

The repository is pre-alpha. A local build passing tests is not sufficient for
a public release or a production claim.

## Current release gates

Completed locally:

- locked Python 3.13 development environment;
- strict lint, formatting, type, and test gates;
- deterministic benchmark with raw schema-valid evidence;
- static and live Wazuh 4.14.6 bridge validation;
- Apache-2.0 license, notice, security policy, contribution guide, code of
  conduct, issue forms, and pull-request template; and
- minimal-permission CI defined for Linux and Windows on Python 3.13 and 3.14.

Still required:

1. finish trademark, confusion, domain, and final repository/package name
   checks described in the provisional name-clearance record;
2. configure a private vulnerability-reporting channel;
3. push the repository and pass the first hosted CI run;
4. enable branch protection, dependency graph, Dependabot, secret scanning,
   private vulnerability reporting, and CodeQL where GitHub supports them;
5. review dependency licenses and generated distribution contents;
6. pass clean-clone installation and distribution smoke tests;
7. obtain two independent reviews, including one MCP review and one
   detection/security review;
8. refresh the benchmark from the exact release-candidate commit;
9. produce an SBOM, SHA-256 checksums, and release notes; and
10. publish a release candidate before considering v0.1.0.

## CI contract

The checked-in CI workflow has read-only repository permissions. Third-party
actions are pinned to reviewed full commit SHAs. It:

- checks the lockfile;
- installs only the locked project environment;
- runs Ruff, strict Pyright, dependency compatibility checks, Wazuh fixture
  validation, and the deterministic benchmark;
- runs the full test suite with an isolated OS temporary directory on Linux and
  Windows with Python 3.13 and 3.14; and
- builds and smoke-tests both the wheel and source distribution.

The workflow exists locally but has not run on GitHub until the repository is
pushed. Do not describe hosted CI as passing before a real run is visible.

## Publication controls

- Keep the package version at `0.0.0` until the final name is approved.
- Do not configure PyPI Trusted Publishing before the final package name and
  repository are fixed.
- Do not use a long-lived PyPI API token.
- Do not publish directly from an unreviewed workstation state.
- Do not attach private audit logs, SQLite databases, approval controls,
  credentials, personal paths, or Docker volumes to a release.
- Create the release from an annotated tag whose commit passed all required
  hosted checks.

## Evidence language

Release notes may report measured results only with the suite version, raw
result file, source commit, machine context, and limitations. They must not say
the proxy prevents all prompt injection, proves universal least privilege, or
is production-ready.
