#!/usr/bin/env python3
"""Strict JSON decoding for security- and release-critical contracts.

The standard Python decoder accepts duplicate keys and non-standard NaN/Infinity
tokens.  It also erases the lexical distinction between canonical and
non-canonical number spellings.  Release evidence must preserve all three
properties so a signer and verifier cannot interpret different documents.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
import json
import re
from typing import Any


_CANONICAL_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_CANONICAL_DECIMAL = re.compile(
    r"-?(?:0|[1-9][0-9]*)(?:\.0|\.[0-9]*[1-9])\Z"
)


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _integer(raw: str) -> int:
    if _CANONICAL_INTEGER.fullmatch(raw) is None or raw == "-0":
        raise ValueError(f"noncanonical JSON integer: {raw}")
    return int(raw)


def _decimal(raw: str) -> float:
    # Release contracts deliberately reject exponent notation and redundant
    # fractional zeroes.  This is a small, deterministic numeric subset and is
    # sufficient for the one fractional metric (CPU seconds) in evidence.
    if _CANONICAL_DECIMAL.fullmatch(raw) is None:
        raise ValueError(f"noncanonical JSON decimal: {raw}")
    try:
        value = Decimal(raw)
    except InvalidOperation as error:
        raise ValueError(f"invalid JSON decimal: {raw}") from error
    if not value.is_finite():
        raise ValueError(f"non-finite JSON decimal: {raw}")
    return float(value)


def _constant(raw: str) -> None:
    raise ValueError(f"non-standard JSON number: {raw}")


def loads(payload: bytes | str) -> Any:
    if isinstance(payload, bytes):
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("JSON input is not UTF-8") from error
    elif isinstance(payload, str):
        text = payload
    else:
        raise TypeError("strict JSON input must be bytes or text")
    try:
        return json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_integer,
            parse_float=_decimal,
            parse_constant=_constant,
        )
    except json.JSONDecodeError as error:
        raise ValueError(f"malformed JSON: {error}") from error


def load(path) -> Any:
    return loads(path.read_bytes())
