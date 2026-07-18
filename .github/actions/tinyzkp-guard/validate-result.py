#!/usr/bin/env python3
"""Strict, dependency-free sanity check for composite-action CLI output."""

import json
import pathlib
import sys


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def load_one(path):
    raw = pathlib.Path(path).read_text(encoding="utf-8")
    decoder = json.JSONDecoder(object_pairs_hook=reject_duplicates)
    value, end = decoder.raw_decode(raw.lstrip())
    if raw.lstrip()[end:].strip():
        raise ValueError("trailing JSON value")
    if not isinstance(value, dict):
        raise ValueError("top level must be an object")
    return value


def validate_job_result(value, expected_status):
    expected = {
        "schema_version",
        "status",
        "requested_mode",
        "selected_mode",
        "estimates",
        "observed_resources",
        "release",
        "proof",
        "verifier_outcome",
        "reason",
        "resumable",
        "checkpoint_relative_path",
    }
    if set(value) != expected or value.get("schema_version") != 1:
        return False
    if value.get("status") != expected_status:
        return False
    if value.get("requested_mode") not in {"auto", "conventional", "bounded"}:
        return False
    if value.get("selected_mode") not in {"conventional", "bounded"}:
        return False
    if not isinstance(value.get("estimates"), dict) or not isinstance(
        value.get("release"), dict
    ):
        return False
    if not isinstance(value.get("resumable"), bool):
        return False
    if expected_status == "interrupted":
        reason = value.get("reason")
        return (
            value["resumable"] is True
            and isinstance(reason, dict)
            and reason.get("code") == "interrupted_resumable"
        )
    return value.get("reason") is None


def validate_error(value):
    if set(value) != {
        "schema_version",
        "engine_release_identity",
        "ok",
        "error",
    }:
        return False
    error = value.get("error")
    return (
        value.get("schema_version") == 1
        and value.get("ok") is False
        and isinstance(value.get("engine_release_identity"), str)
        and isinstance(error, dict)
        and set(error)
        == {
            "class",
            "exit_code",
            "reason",
            "resumable",
            "checkpoint_present",
        }
        and isinstance(error.get("reason"), dict)
    )


def main():
    if len(sys.argv) != 4:
        return 2
    kind, expected_status, path = sys.argv[1:]
    try:
        value = load_one(path)
        valid = (
            validate_job_result(value, expected_status)
            if kind == "job-result"
            else validate_error(value)
            if kind == "error-envelope"
            else False
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        valid = False
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
