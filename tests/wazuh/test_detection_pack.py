"""Static tests for the Wazuh bridge, rules, and fixtures."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from wazuh import lab
from wazuh.verify import load_detection_pack, validate_static_pack

ROOT = Path(__file__).parents[2]


def test_detection_pack_and_all_fixture_pairs_validate() -> None:
    """Every alert rule must have contract-valid positive and near-miss evidence."""
    pack = load_detection_pack()

    validate_static_pack(pack)

    alert_rules = {rule_id for rule_id, rule in pack.rules.items() if rule.level > 0}
    assert len(alert_rules) == 11
    assert len(pack.cases) == 22


def test_agent_ingestion_is_json_only_future_and_source_labeled() -> None:
    """The agent must tail only new JSONL events and attach a namespaced label."""
    root = ET.parse(ROOT / "wazuh" / "config" / "agent-localfile.xml").getroot()
    localfile = root.find("localfile")

    assert root.tag == "ossec_config"
    assert localfile is not None
    assert localfile.findtext("location") == "/var/log/mcp-privprof/events.jsonl"
    assert localfile.findtext("log_format") == "json"
    assert localfile.findtext("only-future-events") == "yes"
    assert localfile.findtext("out_format") == "mcp_privprof: $(log)"
    label = localfile.find("label")
    assert label is not None
    assert label.attrib == {"key": "@source"}
    assert label.text == "mcp_privprof"


def test_custom_decoder_claims_only_prefixed_project_json() -> None:
    """The dedicated decoder must avoid collisions with generic JSON rules."""
    decoder = ET.parse(ROOT / "wazuh" / "decoders" / "mcp_privprof_decoders.xml").getroot()

    assert decoder.tag == "decoder"
    assert decoder.attrib == {"name": "mcp_privprof"}
    prematch = decoder.find("prematch")
    assert prematch is not None
    assert prematch.attrib == {"type": "pcre2"}
    assert prematch.text == r"^mcp_privprof:\s*"
    plugin = decoder.find("plugin_decoder")
    assert plugin is not None
    assert plugin.attrib == {"offset": "after_prematch"}
    assert plugin.text == "JSON_Decoder"


def test_compose_overlay_is_local_only_pinned_and_read_only() -> None:
    """The lab overlay must not expose Wazuh broadly or mutate project evidence."""
    compose = (ROOT / "wazuh" / "compose.override.yml").read_text(encoding="utf-8")

    assert "wazuh/wazuh-agent:4.14.6" in compose
    assert "MCP_PRIVPROF_DECODER_PATH" in compose
    assert "/var/ossec/etc/decoders/mcp_privprof_decoders.xml" in compose
    assert compose.count("127.0.0.1:") == 4
    assert "0.0.0.0:" not in compose
    assert "read_only: true" in compose
    assert "create_host_path: false" in compose
    assert "ports: !override []" in compose


def test_runtime_files_are_generated_from_pinned_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Runtime files must be regular, exact, and separate from tracked inputs."""
    official_root = tmp_path / "official"
    official_config = official_root / "wazuh-agent" / "config" / "wazuh-agent-conf"
    official_config.parent.mkdir(parents=True)
    official_config.write_text("<ossec_config />\n", encoding="utf-8")

    snippet = tmp_path / "agent-localfile.xml"
    snippet.write_text("<ossec_config><localfile /></ossec_config>\n", encoding="utf-8")
    generated_config = tmp_path / "runtime" / "agent-ossec.conf"
    events = tmp_path / "runtime" / "events.jsonl"

    monkeypatch.setattr(lab, "OFFICIAL_ROOT", official_root)
    monkeypatch.setattr(lab, "LOCALFILE_SNIPPET_PATH", snippet)
    monkeypatch.setattr(lab, "AGENT_CONFIG_PATH", generated_config)
    monkeypatch.setattr(lab, "EVENTS_PATH", events)

    lab.prepare_runtime_files()

    assert generated_config.read_text(encoding="utf-8") == (
        "<ossec_config />\n\n<ossec_config><localfile /></ossec_config>\n"
    )
    assert generated_config.is_file()
    assert events.is_file()
    assert events.read_bytes() == b""

    generated_config.write_text("unexpected local change\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="differs from pinned inputs"):
        lab.prepare_runtime_files()
