"""Versioned exact policy constraint boundary models."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, model_validator

type EnumValueV1 = StrictInt | StrictStr


class PathConstraintV1(BaseModel):
    """One symbolic-root containment constraint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["path"]
    argument: str = Field(min_length=1)
    path_roots: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def roots_are_unique(self) -> PathConstraintV1:
        if len(self.path_roots) != len(set(self.path_roots)):
            raise ValueError("path_roots must not contain duplicates")
        return self


class UrlConstraintV1(BaseModel):
    """One exact URL scheme and normalized-host constraint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["url"]
    argument: str = Field(min_length=1)
    schemes: tuple[str, ...] = Field(min_length=1)
    hosts: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def allowlists_are_unique(self) -> UrlConstraintV1:
        if len(self.schemes) != len(set(self.schemes)):
            raise ValueError("schemes must not contain duplicates")
        if len(self.hosts) != len(set(self.hosts)):
            raise ValueError("hosts must not contain duplicates")
        return self


class EnumConstraintV1(BaseModel):
    """One exact integer-or-string enumeration constraint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["enum"]
    argument: str = Field(min_length=1)
    values: tuple[EnumValueV1, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def values_are_unique(self) -> EnumConstraintV1:
        typed = [(type(value), value) for value in self.values]
        if len(typed) != len(set(typed)):
            raise ValueError("enum values must not contain duplicates")
        return self


class MaxUtf8BytesConstraintV1(BaseModel):
    """One UTF-8 byte-length constraint over a string argument."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["max_utf8_bytes"]
    argument: str = Field(min_length=1)
    maximum: StrictInt = Field(ge=0)


type ConstraintV1 = Annotated[
    PathConstraintV1 | UrlConstraintV1 | EnumConstraintV1 | MaxUtf8BytesConstraintV1,
    Field(discriminator="kind"),
]


def validate_constraint_collection(constraints: tuple[ConstraintV1, ...]) -> None:
    """Reject ambiguous duplicate kind/argument entries."""
    keys = [(constraint.kind, constraint.argument) for constraint in constraints]
    if len(keys) != len(set(keys)):
        raise ValueError("constraints must not duplicate an argument and kind")
