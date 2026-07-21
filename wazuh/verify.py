"""Validate the Wazuh detection pack statically and with Wazuh itself."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal, Protocol, cast

from jsonschema import Draft202012Validator, FormatChecker

from mcp_privprof.contracts.event import AuditEventV1

ROOT = Path(__file__).resolve().parent
DECODER_PATH = ROOT / "decoders" / "mcp_privprof_decoders.xml"
RULES_PATH = ROOT / "rules" / "mcp_privprof_rules.xml"
FIXTURES_ROOT = ROOT / "fixtures"
MANIFEST_PATH = FIXTURES_ROOT / "manifest.json"
EVENT_SCHEMA_PATH = ROOT.parent / "schemas" / "event-v1.schema.json"
WAZUH_DECODER_TARGET = "/var/ossec/etc/decoders/mcp_privprof_decoders.xml"
WAZUH_RULES_TARGET = "/var/ossec/etc/rules/mcp_privprof_rules.xml"
EXPECTED_IMAGE = "wazuh/wazuh-manager:4.14.6"
EXPECTED_VERSION = "v4.14.6"
EXPECTED_DECODER = "mcp_privprof"
LOG_PREFIX = "mcp_privprof: "
SOURCE_FIELD = "@source"

type JsonObject = dict[str, object]


class JsonValidator(Protocol):
    """Minimal validator interface needed by fixture loading."""

    def validate(self, instance: object) -> None:
        """Raise when the supplied JSON document violates the schema."""
        ...


@dataclass(frozen=True, slots=True)
class FieldCondition:
    """One exact PCRE2 field condition from a Wazuh rule."""

    name: str
    expression: str


@dataclass(frozen=True, slots=True)
class RuleSpec:
    """Static subset of Wazuh rule semantics used by this detection pack."""

    rule_id: int
    level: int
    conditions: tuple[FieldCondition, ...]
    parent_id: int | None
    matched_parent_id: int | None
    frequency: int | None
    timeframe: int | None
    same_field: str | None

    @property
    def is_correlation(self) -> bool:
        """Return whether this rule depends on prior matched events."""
        return self.matched_parent_id is not None


@dataclass(frozen=True, slots=True)
class FixtureCase:
    """One positive or near-miss fixture expectation."""

    case_id: str
    kind: Literal["positive", "near_miss"]
    target_rule_id: int
    fixture: Path
    expected_rule_id: int
    expected_level: int


@dataclass(frozen=True, slots=True)
class DetectionPack:
    """Parsed and validated rule and fixture inputs."""

    image: str
    decoder_name: str
    source_label: str
    rules: dict[int, RuleSpec]
    cases: tuple[FixtureCase, ...]


def load_detection_pack() -> DetectionPack:
    """Parse rules and manifest, then enforce the static pack contract."""
    decoder_name = _load_decoder_name()
    rules = _load_rules()
    manifest = _load_json_object(MANIFEST_PATH)
    if _required_str(manifest, "schema_version") != "1.0":
        raise ValueError("fixture manifest schema_version must be 1.0")
    image = _required_str(manifest, "wazuh_image")
    if image != EXPECTED_IMAGE:
        raise ValueError(f"Wazuh fixture image must be pinned to {EXPECTED_IMAGE}")
    manifest_decoder = _required_str(manifest, "wazuh_decoder")
    if manifest_decoder != decoder_name:
        raise ValueError(f"fixture manifest decoder must be {decoder_name}")
    source_label = _required_str(manifest, "event_source_label")
    if source_label != "mcp_privprof":
        raise ValueError("event_source_label must be mcp_privprof")
    raw_cases: object = manifest.get("cases")
    if not isinstance(raw_cases, list):
        raise TypeError("fixture manifest cases must be a list")
    case_items = cast(list[object], raw_cases)
    cases = tuple(_parse_case(item) for item in case_items)
    _validate_manifest_coverage(rules, cases)
    return DetectionPack(
        image=image,
        decoder_name=decoder_name,
        source_label=source_label,
        rules=rules,
        cases=cases,
    )


def validate_static_pack(pack: DetectionPack) -> None:
    """Validate event-v1 fixtures and their positive/near-miss semantics."""
    schema = _load_json_object(EVENT_SCHEMA_PATH)
    validator = cast(
        JsonValidator,
        Draft202012Validator(schema, format_checker=FormatChecker()),
    )
    for case in pack.cases:
        events = load_fixture_events(case.fixture, validator=validator)
        enriched = tuple(_with_source_label(event, pack.source_label) for event in events)
        target = pack.rules[case.target_rule_id]
        matched = _case_matches_target(target, enriched, pack.rules)
        if case.kind == "positive" and not matched:
            raise AssertionError(f"{case.case_id} does not match target rule {target.rule_id}")
        if case.kind == "near_miss" and matched:
            raise AssertionError(
                f"{case.case_id} unexpectedly matches target rule {target.rule_id}"
            )
        expected = pack.rules[case.expected_rule_id]
        if expected.level != case.expected_level:
            raise AssertionError(
                f"{case.case_id} expects level {case.expected_level}, "
                f"but rule {expected.rule_id} has level {expected.level}"
            )


def load_fixture_events(
    path: Path,
    *,
    validator: JsonValidator | None = None,
) -> tuple[JsonObject, ...]:
    """Read and contract-validate every JSON object in one JSONL fixture."""
    events: list[JsonObject] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            raise ValueError(f"{path}:{line_number} contains a blank JSONL record")
        try:
            parsed_event: object = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_number} is not valid JSON") from exc
        if not isinstance(parsed_event, dict):
            raise TypeError(f"{path}:{line_number} must contain one JSON object")
        untyped_event = cast(dict[object, object], parsed_event)
        if not all(isinstance(key, str) for key in untyped_event):
            raise TypeError(f"{path}:{line_number} must contain one JSON object")
        document = cast(JsonObject, untyped_event)
        if validator is not None:
            validator.validate(document)
        AuditEventV1.model_validate(document)
        events.append(document)
    if not events:
        raise ValueError(f"{path} must contain at least one event")
    return tuple(events)


def run_wazuh_logtest(pack: DetectionPack) -> None:
    """Run every manifest case against the pinned Wazuh engine in Docker."""
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("Docker is not installed; Wazuh logtest cannot run")
    _require_docker_server(docker)
    image_check = subprocess.run(
        [docker, "image", "inspect", pack.image],
        capture_output=True,
        text=True,
        check=False,
    )
    if image_check.returncode != 0:
        raise RuntimeError(
            f"{pack.image} is not present locally; pull it explicitly before logtest"
        )
    container_name = f"mcp-privprof-wazuh-logtest-{os.getpid()}"
    started = False
    try:
        _start_logtest_container(docker, pack.image, container_name)
        started = True
        _wait_for_analysisd(docker, container_name)
        version = _container_logtest(docker, container_name, ("-V",), input_text="")
        if EXPECTED_VERSION not in version:
            raise RuntimeError(f"expected {EXPECTED_VERSION}, got: {version.strip()}")

        for case in pack.cases:
            events = load_fixture_events(case.fixture)
            input_text = "\n".join(
                LOG_PREFIX
                + json.dumps(
                    _with_source_label(event, pack.source_label),
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                for event in events
            )
            input_text += "\n"
            if len(events) == 1:
                _container_logtest(
                    docker,
                    container_name,
                    (
                        "-q",
                        "-U",
                        f"{case.expected_rule_id}:{case.expected_level}:{pack.decoder_name}",
                    ),
                    input_text=input_text,
                )
            else:
                output = _container_logtest(
                    docker,
                    container_name,
                    ("-v",),
                    input_text=input_text,
                )
                matched_ids = re.findall(r"^\s+id: '([0-9]+)'$", output, flags=re.MULTILINE)
                if not matched_ids or int(matched_ids[-1]) != case.expected_rule_id:
                    raise AssertionError(
                        f"{case.case_id} expected final rule {case.expected_rule_id}; "
                        f"observed {matched_ids or 'no rule IDs'}"
                    )
    finally:
        if started:
            _remove_logtest_container(docker, container_name)


def _load_rules() -> dict[int, RuleSpec]:
    try:
        root = ET.parse(RULES_PATH).getroot()
    except ET.ParseError as exc:
        raise ValueError(f"{RULES_PATH} is not well-formed XML") from exc
    if root.tag != "group" or "mcp_privprof" not in root.attrib.get("name", "").split(","):
        raise ValueError("Wazuh rules must use the mcp_privprof group")

    rules: dict[int, RuleSpec] = {}
    for element in root.findall("rule"):
        rule_id = _required_int_attribute(element, "id")
        level = _required_int_attribute(element, "level")
        if not 100000 <= rule_id <= 120000:
            raise ValueError(f"rule {rule_id} is outside Wazuh's custom rule range")
        if not 0 <= level <= 16:
            raise ValueError(f"rule {rule_id} has an invalid level")
        if rule_id in rules:
            raise ValueError(f"duplicate Wazuh rule ID {rule_id}")
        description = element.findtext("description")
        if description is None or not description.strip():
            raise ValueError(f"rule {rule_id} has no description")
        if element.findtext("options") != "no_full_log":
            raise ValueError(f"rule {rule_id} must suppress full_log duplication")

        conditions: list[FieldCondition] = []
        for field in element.findall("field"):
            name = field.attrib.get("name")
            expression = field.text
            if not name or not expression:
                raise ValueError(f"rule {rule_id} has an incomplete field condition")
            if field.attrib.get("type") != "pcre2":
                raise ValueError(f"rule {rule_id} field {name} must use PCRE2 explicitly")
            if not expression.startswith("^") or not expression.endswith("$"):
                raise ValueError(f"rule {rule_id} field {name} must be fully anchored")
            re.compile(expression)
            conditions.append(FieldCondition(name=name, expression=expression))

        parent_id = _optional_child_int(element, "if_sid")
        matched_parent_id = _optional_child_int(element, "if_matched_sid")
        frequency = _optional_int_attribute(element, "frequency")
        timeframe = _optional_int_attribute(element, "timeframe")
        same_field = element.findtext("same_field")
        if matched_parent_id is None and any(
            item is not None for item in (frequency, timeframe, same_field)
        ):
            raise ValueError(f"rule {rule_id} has incomplete correlation settings")
        if matched_parent_id is not None and (
            frequency is None or timeframe is None or same_field is None
        ):
            raise ValueError(f"rule {rule_id} must fully define its correlation window")

        rules[rule_id] = RuleSpec(
            rule_id=rule_id,
            level=level,
            conditions=tuple(conditions),
            parent_id=parent_id,
            matched_parent_id=matched_parent_id,
            frequency=frequency,
            timeframe=timeframe,
            same_field=same_field,
        )

    if 100000 not in rules:
        raise ValueError("Wazuh pack is missing its event-v1 grouping rule")
    if root.find("rule[@id='100000']/decoded_as") is None:
        raise ValueError("Wazuh grouping rule must declare decoded_as")
    if root.findtext("rule[@id='100000']/decoded_as") != EXPECTED_DECODER:
        raise ValueError(f"Wazuh grouping rule must use decoder {EXPECTED_DECODER}")
    for rule in rules.values():
        for reference in (rule.parent_id, rule.matched_parent_id):
            if reference is not None and reference not in rules:
                raise ValueError(f"rule {rule.rule_id} references missing rule {reference}")
    return rules


def _load_decoder_name() -> str:
    try:
        root = ET.parse(DECODER_PATH).getroot()
    except ET.ParseError as exc:
        raise ValueError(f"{DECODER_PATH} is not well-formed XML") from exc
    name = root.attrib.get("name")
    if root.tag != "decoder" or name != EXPECTED_DECODER:
        raise ValueError(f"Wazuh decoder must be named {EXPECTED_DECODER}")
    prematch = root.find("prematch")
    if (
        prematch is None
        or prematch.attrib.get("type") != "pcre2"
        or prematch.text != r"^mcp_privprof:\s*"
    ):
        raise ValueError("Wazuh decoder must require the exact project transport prefix")
    plugin = root.find("plugin_decoder")
    if (
        plugin is None
        or plugin.attrib.get("offset") != "after_prematch"
        or plugin.text != "JSON_Decoder"
    ):
        raise ValueError("Wazuh decoder must parse JSON after the project prefix")
    return name


def _parse_case(value: object) -> FixtureCase:
    if not isinstance(value, dict):
        raise TypeError("each fixture case must be an object")
    untyped_item = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in untyped_item):
        raise TypeError("each fixture case must be an object")
    item = cast(JsonObject, untyped_item)
    case_id = _required_str(item, "case_id")
    raw_kind = _required_str(item, "kind")
    if raw_kind not in {"positive", "near_miss"}:
        raise ValueError(f"{case_id} has an invalid fixture kind")
    kind = cast(Literal["positive", "near_miss"], raw_kind)
    fixture_relative = Path(_required_str(item, "fixture"))
    fixture = (FIXTURES_ROOT / fixture_relative).resolve()
    if not fixture.is_relative_to(FIXTURES_ROOT.resolve()) or not fixture.is_file():
        raise ValueError(f"{case_id} fixture must be an existing file under wazuh/fixtures")
    return FixtureCase(
        case_id=case_id,
        kind=kind,
        target_rule_id=_required_int(item, "target_rule_id"),
        fixture=fixture,
        expected_rule_id=_required_int(item, "expected_rule_id"),
        expected_level=_required_int(item, "expected_level"),
    )


def _validate_manifest_coverage(
    rules: dict[int, RuleSpec],
    cases: tuple[FixtureCase, ...],
) -> None:
    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("fixture case IDs must be unique")
    for case in cases:
        if case.target_rule_id not in rules or case.expected_rule_id not in rules:
            raise ValueError(f"{case.case_id} references an unknown Wazuh rule")
    alert_rule_ids = {rule_id for rule_id, rule in rules.items() if rule.level > 0}
    for rule_id in alert_rule_ids:
        kinds = {case.kind for case in cases if case.target_rule_id == rule_id}
        if kinds != {"positive", "near_miss"}:
            raise ValueError(f"rule {rule_id} needs one positive and one near-miss case")


def _case_matches_target(
    target: RuleSpec,
    events: tuple[JsonObject, ...],
    rules: dict[int, RuleSpec],
) -> bool:
    if not target.is_correlation:
        return any(_event_matches_rule(target, event, rules) for event in events)
    assert target.matched_parent_id is not None
    assert target.frequency is not None
    assert target.timeframe is not None
    assert target.same_field is not None
    parent = rules[target.matched_parent_id]
    matches_by_value: dict[str, list[datetime]] = {}
    for event in events:
        if not _event_matches_rule(parent, event, rules):
            continue
        value = event.get(target.same_field)
        timestamp = event.get("timestamp")
        if not isinstance(value, str) or not isinstance(timestamp, str):
            continue
        when = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        prior = matches_by_value.setdefault(value, [])
        prior.append(when)
        within_window = [
            candidate
            for candidate in prior
            if 0 <= (when - candidate).total_seconds() <= target.timeframe
        ]
        matches_by_value[value] = within_window
        if len(within_window) >= target.frequency:
            return True
    return False


def _event_matches_rule(
    rule: RuleSpec,
    event: JsonObject,
    rules: dict[int, RuleSpec],
) -> bool:
    if rule.parent_id is not None and not _event_matches_rule(rules[rule.parent_id], event, rules):
        return False
    for condition in rule.conditions:
        value = event.get(condition.name)
        if not isinstance(value, str) or re.search(condition.expression, value) is None:
            return False
    return True


def _with_source_label(event: JsonObject, source_label: str) -> JsonObject:
    enriched = dict(event)
    if SOURCE_FIELD in enriched:
        raise ValueError(f"event-v1 fixture must not define reserved Wazuh field {SOURCE_FIELD}")
    enriched[SOURCE_FIELD] = source_label
    return enriched


def _start_logtest_container(docker: str, image: str, container_name: str) -> None:
    existing = subprocess.run(
        [
            docker,
            "ps",
            "-a",
            "--filter",
            f"name=^/{container_name}$",
            "--format",
            "{{.Names}}",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if existing.returncode != 0:
        raise RuntimeError(f"could not inspect Docker containers: {existing.stderr.strip()}")
    if existing.stdout.strip():
        raise RuntimeError(f"refusing to reuse existing container {container_name}")

    decoder_mount = f"type=bind,src={DECODER_PATH.resolve()},dst={WAZUH_DECODER_TARGET},readonly"
    rules_mount = f"type=bind,src={RULES_PATH.resolve()},dst={WAZUH_RULES_TARGET},readonly"
    started = subprocess.run(
        [
            docker,
            "run",
            "-d",
            "--name",
            container_name,
            "--pull=never",
            "--network=none",
            "--label",
            "org.mcp-privprof.role=wazuh-logtest",
            "--mount",
            decoder_mount,
            "--mount",
            rules_mount,
            image,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if started.returncode != 0:
        raise RuntimeError(f"could not start temporary Wazuh manager: {started.stderr.strip()}")


def _wait_for_analysisd(docker: str, container_name: str) -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        status = subprocess.run(
            [docker, "exec", container_name, "/var/ossec/bin/wazuh-control", "status"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if "wazuh-analysisd is running" in status.stdout:
            return
        state = subprocess.run(
            [docker, "inspect", "--format", "{{.State.Status}}", container_name],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if state.returncode != 0 or state.stdout.strip() != "running":
            logs = _container_logs(docker, container_name)
            raise RuntimeError(f"temporary Wazuh manager stopped before readiness:\n{logs}")
        time.sleep(1)
    logs = _container_logs(docker, container_name)
    raise TimeoutError(f"wazuh-analysisd did not become ready within 90 seconds:\n{logs}")


def _container_logs(docker: str, container_name: str) -> str:
    completed = subprocess.run(
        [docker, "logs", "--tail", "100", container_name],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    return completed.stdout + completed.stderr


def _remove_logtest_container(docker: str, container_name: str) -> None:
    removed = subprocess.run(
        [docker, "rm", "-f", container_name],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if removed.returncode != 0 and "No such container" not in removed.stderr:
        raise RuntimeError(
            f"could not remove temporary Wazuh manager {container_name}: {removed.stderr.strip()}"
        )


def _container_logtest(
    docker: str,
    container_name: str,
    arguments: tuple[str, ...],
    *,
    input_text: str,
) -> str:
    completed = subprocess.run(
        [
            docker,
            "exec",
            "-i",
            container_name,
            "/var/ossec/bin/wazuh-logtest",
            *arguments,
        ],
        input=input_text,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    output = completed.stdout + completed.stderr
    if completed.returncode != 0:
        raise AssertionError(f"wazuh-logtest failed:\n{output}")
    return output


def _require_docker_server(docker: str) -> None:
    completed = subprocess.run(
        [docker, "version", "--format", "{{.Server.Version}}"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise RuntimeError("Docker Desktop is installed but its engine is not running")


def _load_json_object(path: Path) -> JsonObject:
    value: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{path} must contain a JSON object")
    untyped_value = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in untyped_value):
        raise TypeError(f"{path} must contain a JSON object")
    return cast(JsonObject, untyped_value)


def _required_str(value: JsonObject, key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise TypeError(f"{key} must be a non-empty string")
    return item


def _required_int(value: JsonObject, key: str) -> int:
    item = value.get(key)
    if not isinstance(item, int) or isinstance(item, bool):
        raise TypeError(f"{key} must be an integer")
    return item


def _required_int_attribute(element: ET.Element, key: str) -> int:
    value = element.attrib.get(key)
    if value is None:
        raise ValueError(f"rule is missing {key}")
    return int(value)


def _optional_int_attribute(element: ET.Element, key: str) -> int | None:
    value = element.attrib.get(key)
    return int(value) if value is not None else None


def _optional_child_int(element: ET.Element, name: str) -> int | None:
    value = element.findtext(name)
    return int(value) if value is not None else None


def main() -> int:
    """Run the requested verification level."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--logtest",
        action="store_true",
        help="also run all cases in the locally installed Wazuh 4.14.6 Docker image",
    )
    args = parser.parse_args()
    try:
        pack = load_detection_pack()
        validate_static_pack(pack)
        print(f"Static Wazuh pack validation passed ({len(pack.cases)} cases).")
        if args.logtest:
            run_wazuh_logtest(pack)
            print(f"Wazuh {EXPECTED_VERSION} logtest passed ({len(pack.cases)} cases).")
    except Exception as exc:
        print(f"Wazuh pack verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
