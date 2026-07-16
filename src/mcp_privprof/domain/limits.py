"""Exact, human-reviewed call limits."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class LimitType(StrEnum):
    """Stable limit identities for decisions and audit events."""

    NONE = "none"
    CALLS_PER_MINUTE = "calls_per_minute"
    CALLS_PER_TASK = "calls_per_task"
    CONCURRENT_CALLS = "concurrent_calls"


@dataclass(frozen=True, slots=True)
class ToolLimits:
    """Positive finite integer limits for one exact tool rule."""

    max_calls_per_minute: int
    max_calls_per_task: int
    max_concurrent_calls: int

    def __post_init__(self) -> None:
        for label, value in (
            ("max_calls_per_minute", self.max_calls_per_minute),
            ("max_calls_per_task", self.max_calls_per_task),
            ("max_concurrent_calls", self.max_concurrent_calls),
        ):
            if type(value) is not int or not 1 <= value <= 1_000_000:
                raise ValueError(f"{label} must be an integer from 1 to 1000000")
