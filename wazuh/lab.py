"""Prepare and operate the pinned, local-only Wazuh integration lab."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
RUNTIME_ROOT = REPOSITORY_ROOT / ".mcp-privprof" / "wazuh-lab"
OFFICIAL_ROOT = RUNTIME_ROOT / "wazuh-docker"
OFFICIAL_TAG = "v4.14.6"
OFFICIAL_COMMIT = "499184cbeb44fc1086791d11ad4b9bdcb77a9bb9"
OFFICIAL_URL = "https://github.com/wazuh/wazuh-docker.git"
OFFICIAL_FILE_HASHES = {
    "single-node/docker-compose.yml": (
        "dbc57d3d516d9c37cdee9e17f7b1c6c087febf4af3797e17aa8399e5114f0b5d"
    ),
    "single-node/generate-indexer-certs.yml": (
        "4b31500fbed66af15599464c686988e0900089e7ea8aeb53bedb6f88ba68db08"
    ),
    "wazuh-agent/config/wazuh-agent-conf": (
        "2d0689646b4b9aa9ac627ada3c6bc7ea43ad32d64106096691a1569e70f76307"
    ),
}
AGENT_CONFIG_PATH = RUNTIME_ROOT / "agent-ossec.conf"
EVENTS_PATH = REPOSITORY_ROOT / ".mcp-privprof" / "events.jsonl"
RULES_PATH = REPOSITORY_ROOT / "wazuh" / "rules" / "mcp_privprof_rules.xml"
LOCALFILE_SNIPPET_PATH = REPOSITORY_ROOT / "wazuh" / "config" / "agent-localfile.xml"
OVERRIDE_PATH = REPOSITORY_ROOT / "wazuh" / "compose.override.yml"
BASE_COMPOSE_PATH = OFFICIAL_ROOT / "single-node" / "docker-compose.yml"
CERT_COMPOSE_PATH = OFFICIAL_ROOT / "single-node" / "generate-indexer-certs.yml"
CERT_DIRECTORY = OFFICIAL_ROOT / "single-node" / "config" / "wazuh_indexer_ssl_certs"
CERTIFICATE_NAMES = {
    "root-ca.pem",
    "root-ca-manager.pem",
    "wazuh.manager.pem",
    "wazuh.manager-key.pem",
    "wazuh.indexer.pem",
    "wazuh.indexer-key.pem",
    "wazuh.dashboard.pem",
    "wazuh.dashboard-key.pem",
    "admin.pem",
    "admin-key.pem",
}
PROJECT_NAME = "mcp-privprof-wazuh"
MINIMUM_COMPOSE_VERSION = (2, 24, 4)


def prepare() -> None:
    """Fetch and verify official inputs, then create ignored local runtime files."""
    RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
    if not OFFICIAL_ROOT.exists():
        git = _require_executable("git")
        _run(
            (
                git,
                "clone",
                "--depth",
                "1",
                "--branch",
                OFFICIAL_TAG,
                OFFICIAL_URL,
                str(OFFICIAL_ROOT),
            ),
            timeout=180,
        )
    _verify_official_checkout()
    prepare_runtime_files()


def validate_compose() -> None:
    """Resolve the official base and project overlay without starting containers."""
    prepare()
    docker = _require_docker()
    _run((*_compose_prefix(docker), "config", "--quiet"), env=_compose_environment())


def start() -> None:
    """Generate official certificates if needed, then start the local Wazuh lab."""
    prepare()
    docker = _require_docker()
    _ensure_certificates(docker)
    _run((*_compose_prefix(docker), "up", "-d"), env=_compose_environment(), timeout=600)


def stop() -> None:
    """Stop containers while retaining named Wazuh volumes and evidence."""
    docker = _require_docker()
    if not BASE_COMPOSE_PATH.is_file():
        raise RuntimeError("Wazuh lab is not prepared")
    _run((*_compose_prefix(docker), "down"), env=_compose_environment(), timeout=180)


def status() -> None:
    """Show the current state of the Wazuh lab containers."""
    docker = _require_docker()
    if not BASE_COMPOSE_PATH.is_file():
        raise RuntimeError("Wazuh lab is not prepared")
    _run((*_compose_prefix(docker), "ps"), env=_compose_environment())


def _verify_official_checkout() -> None:
    git = _require_executable("git")
    if not (OFFICIAL_ROOT / ".git").is_dir():
        raise RuntimeError(f"{OFFICIAL_ROOT} exists but is not an official Git checkout")
    commit = _capture((git, "-C", str(OFFICIAL_ROOT), "rev-parse", "HEAD")).strip()
    if commit != OFFICIAL_COMMIT:
        raise RuntimeError(f"expected official commit {OFFICIAL_COMMIT}, found {commit}")
    changed = subprocess.run(
        (git, "-C", str(OFFICIAL_ROOT), "diff", "--quiet"),
        check=False,
    )
    if changed.returncode != 0:
        raise RuntimeError("official Wazuh tracked files have local modifications")
    for relative, expected_hash in OFFICIAL_FILE_HASHES.items():
        path = OFFICIAL_ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"official Wazuh file is missing: {relative}")
        actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            raise RuntimeError(f"official Wazuh file hash mismatch: {relative}")


def prepare_runtime_files() -> None:
    """Create exact local runtime files from already verified project inputs."""
    _prepare_agent_config()
    _prepare_events_file()


def _prepare_agent_config() -> None:
    official = OFFICIAL_ROOT / "wazuh-agent" / "config" / "wazuh-agent-conf"
    snippet = LOCALFILE_SNIPPET_PATH.read_text(encoding="utf-8").strip()
    expected = official.read_text(encoding="utf-8").rstrip() + "\n\n" + snippet + "\n"
    if AGENT_CONFIG_PATH.exists():
        if AGENT_CONFIG_PATH.is_symlink() or not AGENT_CONFIG_PATH.is_file():
            raise RuntimeError("generated Wazuh agent configuration is not a regular file")
        if AGENT_CONFIG_PATH.read_text(encoding="utf-8") != expected:
            raise RuntimeError(
                "generated Wazuh agent configuration differs from pinned inputs; "
                "inspect it before replacing"
            )
        return
    _atomic_write(AGENT_CONFIG_PATH, expected.encode())


def _prepare_events_file() -> None:
    EVENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    if EVENTS_PATH.is_symlink():
        raise RuntimeError("Wazuh event path must not be a symbolic link")
    if EVENTS_PATH.exists() and not EVENTS_PATH.is_file():
        raise RuntimeError("Wazuh event path must be a regular file")
    if not EVENTS_PATH.exists():
        _atomic_write(EVENTS_PATH, b"")


def _ensure_certificates(docker: str) -> None:
    present: set[str] = (
        {path.name for path in CERT_DIRECTORY.glob("*.pem")} if CERT_DIRECTORY.exists() else set()
    )
    if present >= CERTIFICATE_NAMES:
        return
    if present:
        missing = ", ".join(sorted(CERTIFICATE_NAMES - present))
        raise RuntimeError(f"Wazuh certificate directory is incomplete; missing: {missing}")
    _run(
        (
            docker,
            "compose",
            "-p",
            PROJECT_NAME,
            "-f",
            str(CERT_COMPOSE_PATH),
            "run",
            "--rm",
            "generator",
        ),
        timeout=300,
    )
    generated = {path.name for path in CERT_DIRECTORY.glob("*.pem")}
    if not generated >= CERTIFICATE_NAMES:
        missing = ", ".join(sorted(CERTIFICATE_NAMES - generated))
        raise RuntimeError(f"Wazuh certificate generation was incomplete; missing: {missing}")


def _require_docker() -> str:
    docker = _require_executable("docker")
    server_version = _capture(
        (docker, "version", "--format", "{{.Server.Version}}"),
        failure="Docker Desktop is installed but its engine is not running",
    ).strip()
    if not server_version:
        raise RuntimeError("Docker Desktop returned no engine version")
    compose_version = _capture((docker, "compose", "version", "--short")).strip()
    match = re.match(r"^v?([0-9]+)\.([0-9]+)\.([0-9]+)", compose_version)
    if match is None:
        raise RuntimeError(f"could not parse Docker Compose version: {compose_version}")
    parsed = tuple(int(group) for group in match.groups())
    if parsed < MINIMUM_COMPOSE_VERSION:
        required = ".".join(str(item) for item in MINIMUM_COMPOSE_VERSION)
        raise RuntimeError(f"Docker Compose {required} or newer is required")
    return docker


def _compose_prefix(docker: str) -> tuple[str, ...]:
    return (
        docker,
        "compose",
        "-p",
        PROJECT_NAME,
        "-f",
        str(BASE_COMPOSE_PATH),
        "-f",
        str(OVERRIDE_PATH),
    )


def _compose_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "MCP_PRIVPROF_RULES_PATH": str(RULES_PATH.resolve()),
            "MCP_PRIVPROF_AGENT_CONFIG_PATH": str(AGENT_CONFIG_PATH.resolve()),
            "MCP_PRIVPROF_EVENTS_PATH": str(EVENTS_PATH.resolve()),
        }
    )
    return environment


def _require_executable(name: str) -> str:
    executable = shutil.which(name)
    if executable is None:
        raise RuntimeError(f"required executable is not installed: {name}")
    return executable


def _capture(command: tuple[str, ...], *, failure: str | None = None) -> str:
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        message = failure or f"command failed: {' '.join(command)}"
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(f"{message}: {detail}")
    return completed.stdout


def _run(
    command: tuple[str, ...],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 120,
) -> None:
    completed = subprocess.run(
        command,
        env=env,
        check=False,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"command failed with exit code {completed.returncode}")


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        temporary_path.replace(path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def main() -> int:
    """Dispatch one explicit Wazuh lab operation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("prepare", "config", "up", "down", "status"),
        help="operation to perform",
    )
    args = parser.parse_args()
    operations = {
        "prepare": prepare,
        "config": validate_compose,
        "up": start,
        "down": stop,
        "status": status,
    }
    try:
        operations[args.command]()
    except Exception as exc:
        print(f"Wazuh lab operation failed: {exc}", file=sys.stderr)
        return 1
    print(f"Wazuh lab {args.command} completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
