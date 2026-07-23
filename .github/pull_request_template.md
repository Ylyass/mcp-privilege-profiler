## Purpose

Explain the problem and the smallest change that solves it.

## Security impact

- Trust boundary changed:
- New permissions, data, or transports:
- Failure behavior:
- Threat-model or ADR updates:

## Verification

- [ ] Tests added or updated
- [ ] `uv run ruff check .`
- [ ] `uv run ruff format --check .`
- [ ] `uv run pyright`
- [ ] `uv run pytest`
- [ ] `uv run python -m wazuh.verify` when detection behavior is affected
- [ ] Documentation and changelog updated
- [ ] No secrets, personal paths, raw sensitive arguments, or unrelated artifacts added

## Evidence

Provide concise test output or a link to the CI run. Do not paste credentials,
production data, or destructive proof-of-concept payloads.
