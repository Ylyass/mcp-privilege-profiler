# ADR 0006: Reviewed constraints and exact enforcement

Status: accepted
Date: 2026-07-15

## Context

A policy effect alone can be too broad. A file-reading tool may be appropriate
for one project root but not the entire machine, and an HTTP tool may be
appropriate for one destination but not arbitrary hosts.

Adding constraints directly to a generated policy after human review would
break provenance: the enforced artifact would contain decisions not present in
the evidence-bound review. A programmable policy language would also increase
ambiguity and attack surface.

## Decision

Store constraints on each review decision and copy them unchanged into the
generated policy. Support only four exact, versioned constraint types in v1:

- resolved containment within configured symbolic path roots;
- exact normalized URL schemes and hosts, with default ports only;
- exact integer or string enums; and
- maximum strict UTF-8 byte length.

Require `default_effect: DENY`, exact server and tool identities, complete
policy coverage of the approved catalog, and an exact complete-tool
fingerprint before enforce mode starts.

Filter `tools/list` to `ALLOW` and `REQUIRE_APPROVAL`. Evaluate permission and
constraints before forwarding. `REQUIRE_APPROVAL` returns a stable error until
the separate Stage 8 permit workflow exists.

## Consequences

The enforced decision remains traceable to one completed review. Missing
entries, stale definitions, missing root bindings, ambiguous paths, and URL
normalization tricks fail closed.

The policy format is intentionally less expressive than a general policy
language. New constraint kinds require a versioned contract, domain invariant,
storage codec, evaluator, and adversarial tests. Limits, mandatory audit, and
permit consumption remain separate Stage 8 work.
