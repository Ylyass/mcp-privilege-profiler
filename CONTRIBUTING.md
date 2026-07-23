# Contributing

Thank you for improving MCP Privilege Profiler.

Before opening a pull request:

1. Keep changes narrowly scoped.
2. Add or update tests for behavior changes.
3. Update documentation and ADRs when a security boundary changes.
4. Do not add raw secrets, credentials, or real destructive test cases.
5. Run the same local gates used by CI:

       uv lock --check
       uv sync --locked --all-extras
       uv run ruff check .
       uv run ruff format --check .
       uv run pyright
       uv run python scripts/run_pytest.py
       uv run python -m wazuh.verify

6. Use the issue and pull-request templates; do not place vulnerability details
   in a public issue.

Security-sensitive changes must state their threat-model impact and failure
behavior.

Install the repository-owned local checks once per clone:

    uv run pre-commit install --hook-type pre-commit --hook-type pre-push

The commit hook checks whitespace, Ruff lint, and formatting. The push hook
also runs strict Pyright, the full pytest suite in a private OS temporary
directory, and static Wazuh validation.
