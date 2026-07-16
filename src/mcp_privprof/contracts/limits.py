"""Versioned per-tool limit boundary model."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, StrictInt


class ToolLimitsV1(BaseModel):
    """Strict positive call limits copied from human review into policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_calls_per_minute: StrictInt = Field(ge=1, le=1_000_000)
    max_calls_per_task: StrictInt = Field(ge=1, le=1_000_000)
    max_concurrent_calls: StrictInt = Field(ge=1, le=1_000_000)
