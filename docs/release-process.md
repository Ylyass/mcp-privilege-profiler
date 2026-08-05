# Release and open-source publication process

The source repository is public as a pre-alpha project. Public source and a
passing local build are not the same as a versioned release or a production
claim.

## Current release gates

Completed for public source publication:

- locked Python 3.13 development environment;
- stable MCP Python SDK 2.0.0 migration with current-protocol negotiation and
  a passing automated suite;
- strict lint, formatting, type, and test gates;
- deterministic benchmark with raw schema-valid evidence;
- static and live Wazuh 4.14.6 bridge validation;
- post-SDK2 sealed real-Claude profiling evidence from two controlled runs and six expected
  read-only MCP calls;
- explicit human review and a successful enforced Claude task through the
  three-tool reviewed catalog;
- a tested source-checkout safe demo with an allowed path and direct hidden-tool
  denial;
- locally built wheel and source distribution smoke tests, plus archive
  inspection confirming that ignored caches, runtime state, databases, personal
  documents, and private-key file types are absent;
- a post-migration clean-tree simulation that copied all 197 tracked files into
  a fresh OS-temporary directory, created a new locked environment, ran the
  installed CLI, and passed the safe demo;
- Apache-2.0 license, notice, security policy, contribution guide, code of
  conduct, issue forms, and pull-request template; and
- selected `mcp-privilege-profiler` public repository identifier, package
  metadata, and a documented GitHub private-reporting path; and
- a locked-runtime vulnerability and licence review, including remediation of
  CVE-2026-69247 by raising `cryptography` to 50.0.0; and
- a public GitHub source repository with dependency graph, Dependabot alerts,
  security updates, and malware alerts enabled; and
- minimal-permission hosted CI passing on Linux and Windows with Python 3.13 and
  3.14 at publication commit `e4f54a82627d8e8b85fdc840e9e1741e12775042`.

The real-Claude profile, review, direct enforcement preflight, and real-agent
enforcement were repeated after the SDK v2 migration from clean commit
`beaa6e9`. The earlier real-Wazuh engine and live-ingestion results remain
historical evidence. The deterministic benchmark was refreshed after the
executable profile-lifecycle changes and passed 75/75 cases from clean commit
`3f7ba2a`. Distribution build and isolated wheel/source smoke tests also pass
locally.

Still required:

1. refresh the real Wazuh engine/live probe on the final SDK v2
   release-candidate commit;
2. finish trademark and confusion checks for package publication as described
   in the name-clearance record;
3. enable and test GitHub private vulnerability reporting;
4. enable branch protection, secret scanning, and CodeQL where GitHub supports
   them;
5. repeat the dependency vulnerability/licence review and distribution
   inspection against the exact release-candidate commit;
6. pass an independent GitHub clean-clone install/demo review and repeat
   distribution smoke tests on the exact release-candidate commit;
7. obtain two independent reviews, including one MCP review and one
   detection/security review;
8. produce an SBOM, SHA-256 checksums, and release notes; and
9. publish a release candidate before considering v0.1.0.

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

The workflow passed in the public GitHub repository at publication commit
`e4f54a82627d8e8b85fdc840e9e1741e12775042`. Every release tag must trigger and
pass the same required checks; one green historical run is not a permanent
guarantee.

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
