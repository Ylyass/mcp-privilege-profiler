# Release and open-source publication process

The repository is pre-alpha. A local build passing tests is not sufficient for
a public release or a production claim.

## Current release gates

Completed locally:

- locked Python 3.13 development environment;
- stable MCP Python SDK 2.0.0 migration with current-protocol negotiation and
  a passing automated suite;
- strict lint, formatting, type, and test gates;
- deterministic benchmark with raw schema-valid evidence;
- static and live Wazuh 4.14.6 bridge validation;
- sealed real-Claude profiling evidence from two controlled runs and six expected
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
- minimal-permission CI defined for Linux and Windows on Python 3.13 and 3.14.

The real-Claude and live-Wazuh items in the completed-local list were produced
before the SDK v2 migration. They are retained as historical evidence, not
accepted as release-candidate evidence. The SDK v2 benchmark passed 75/75 cases
from clean commit `51cfe43`; post-migration distribution and clean-tree checks
also pass. The benchmark remains valid for that source revision and must be
repeated if executable code or locked dependencies change before the final
candidate.

Still required:

1. refresh the real-Claude profiling/enforcement and real Wazuh engine/live
   probe on the SDK v2 release-candidate commit, repeating the benchmark only
   if executable code or locked dependencies change;
2. finish trademark and confusion checks for package publication as described
   in the name-clearance record;
3. enable and test GitHub private vulnerability reporting after the repository
   exists;
4. push the repository and pass the first hosted CI run;
5. enable branch protection, dependency graph, Dependabot, secret scanning,
   private vulnerability reporting, and CodeQL where GitHub supports them;
6. repeat the dependency vulnerability/licence review and distribution
   inspection against the exact release-candidate commit;
7. pass an independent GitHub clean-clone install/demo review and repeat
   distribution smoke tests on the exact release-candidate commit;
8. obtain two independent reviews, including one MCP review and one
   detection/security review;
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
