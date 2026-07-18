#!/usr/bin/env python3
"""Strict, dependency-free validation for composite-action Guard output."""

import json
import pathlib
import re
import sys


UINT64_MAX = (1 << 64) - 1
COMPATIBILITY_PROFILE = "tinyzkp-p3-goldilocks-v1"
HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
RELATIVE_PATH = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9._/-]{1,1024}$")

CLASS_EXIT = {
    "incompatible": 10,
    "invalid_input": 11,
    "insufficient_resources": 12,
    "resumable_interruption": 13,
    "corrupt_checkpoint": 14,
    "verification_failure": 15,
    "license_failure": 16,
    "internal_error": 70,
}

CLASS_REMEDIATION = {
    "incompatible": "use_supported_profile",
    "invalid_input": "repair_local_input",
    "insufficient_resources": "increase_budget_or_capacity",
    "resumable_interruption": "resume_exact_release",
    "corrupt_checkpoint": "restore_or_restart_job",
    "verification_failure": "retain_artifacts_and_report",
    "license_failure": "activate_eligible_release",
    "internal_error": "generate_support_report",
}

REASONS = {
    "unsupported_platform": (
        "incompatible",
        "Production proving requires Linux x86-64.",
    ),
    "unsupported_profile": (
        "incompatible",
        "The declared proof profile is unsupported.",
    ),
    "unsupported_air_feature": (
        "incompatible",
        "The AIR uses a feature outside the v1 profile.",
    ),
    "manifest_contract_invalid": (
        "invalid_input",
        "The job manifest or declaration is invalid.",
    ),
    "unsafe_path": ("invalid_input", "A configured path is unsafe."),
    "input_limit_exceeded": (
        "invalid_input",
        "A local input exceeds a published limit.",
    ),
    "ram_budget_insufficient": (
        "insufficient_resources",
        "The RAM budget is below the required capacity.",
    ),
    "scratch_budget_insufficient": (
        "insufficient_resources",
        "The scratch budget is below the estimate plus headroom.",
    ),
    "scratch_space_insufficient": (
        "insufficient_resources",
        "Available scratch space is below the estimate plus headroom.",
    ),
    "job_state_exists": (
        "invalid_input",
        "The requested job directory already contains state.",
    ),
    "interrupted_resumable": (
        "resumable_interruption",
        "The proof was interrupted and can resume.",
    ),
    "checkpoint_missing": ("corrupt_checkpoint", "The expected checkpoint is missing."),
    "checkpoint_corrupt": ("corrupt_checkpoint", "The checkpoint is corrupt."),
    "checkpoint_release_mismatch": (
        "corrupt_checkpoint",
        "The checkpoint belongs to another exact release.",
    ),
    "job_not_resumable": (
        "invalid_input",
        "The job is not in a resumable state.",
    ),
    "verification_rejected": (
        "verification_failure",
        "The ordinary verifier rejected the proof.",
    ),
    "release_not_activated": (
        "license_failure",
        "This exact release is not activated.",
    ),
    "license_inactive": (
        "license_failure",
        "The subscription license is inactive.",
    ),
    "license_provider_unavailable": (
        "license_failure",
        "The license provider is unavailable.",
    ),
    "engine_artifact_mismatch": (
        "internal_error",
        "The engine artifact does not match the release.",
    ),
    "engine_protocol_invalid": (
        "internal_error",
        "The local engine protocol is invalid.",
    ),
    "release_identity_mismatch": (
        "internal_error",
        "Release identities do not match.",
    ),
    "internal_error": (
        "internal_error",
        "The local program encountered an internal error.",
    ),
}

RESOURCE_REASONS = {
    "input_limit_exceeded",
    "ram_budget_insufficient",
    "scratch_budget_insufficient",
    "scratch_space_insufficient",
}
PLATFORMS = {"linux_x86_64", "linux_other", "macos", "windows", "other"}
PROFILES = {"tinyzkp_p3_goldilocks_v1", "other"}


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def load_one(path):
    raw = pathlib.Path(path).read_text(encoding="utf-8")
    stripped = raw.lstrip()
    decoder = json.JSONDecoder(object_pairs_hook=reject_duplicates)
    value, end = decoder.raw_decode(stripped)
    if stripped[end:].strip():
        raise ValueError("trailing JSON value")
    if not isinstance(value, dict):
        raise ValueError("top level must be an object")
    return value


def exact_object(value, keys):
    return isinstance(value, dict) and set(value) == set(keys)


def uint64(value):
    return type(value) is int and 0 <= value <= UINT64_MAX


def optional_uint64(value):
    return value is None or uint64(value)


def lower_hex_digest(value):
    return isinstance(value, str) and HEX_DIGEST.fullmatch(value) is not None


def safe_release_identity(value):
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 256
        and value.isascii()
        and all(character.isalnum() or character in "._:-+/" for character in value)
        and not value.startswith("/")
        and ".." not in value
        and "//" not in value
    )


def safe_relative_path(value):
    return isinstance(value, str) and RELATIVE_PATH.fullmatch(value) is not None


def validate_reason(value):
    keys = {
        "code",
        "class",
        "summary",
        "remediation",
        "docs_url",
        "required_bytes",
        "available_bytes",
        "limit_bytes",
        "expected_platform",
        "detected_platform",
        "expected_profile",
        "detected_profile",
    }
    if not exact_object(value, keys):
        return False
    code = value["code"]
    specification = REASONS.get(code)
    if specification is None:
        return False
    reason_class, summary = specification
    if (
        value["class"] != reason_class
        or value["summary"] != summary
        or value["remediation"] != CLASS_REMEDIATION[reason_class]
        or value["docs_url"] != f"/troubleshooting#{code}"
    ):
        return False
    resources = (
        value["required_bytes"],
        value["available_bytes"],
        value["limit_bytes"],
    )
    if not all(optional_uint64(item) for item in resources):
        return False
    if code not in RESOURCE_REASONS and any(item is not None for item in resources):
        return False

    expected_platform = value["expected_platform"]
    detected_platform = value["detected_platform"]
    if (
        expected_platform is not None
        and expected_platform not in PLATFORMS
        or detected_platform is not None
        and detected_platform not in PLATFORMS
    ):
        return False
    if expected_platform is not None or detected_platform is not None:
        if code != "unsupported_platform" or expected_platform != "linux_x86_64":
            return False

    expected_profile = value["expected_profile"]
    detected_profile = value["detected_profile"]
    if (
        expected_profile is not None
        and expected_profile not in PROFILES
        or detected_profile is not None
        and detected_profile not in PROFILES
    ):
        return False
    if expected_profile is not None or detected_profile is not None:
        if (
            code != "unsupported_profile"
            or expected_profile != "tinyzkp_p3_goldilocks_v1"
        ):
            return False
    return True


def validate_estimate(value):
    keys = {
        "peak_resident_bytes",
        "scratch_high_water_bytes",
        "total_read_bytes",
        "total_write_bytes",
    }
    return exact_object(value, keys) and all(uint64(value[key]) for key in keys)


def validate_estimates(value):
    return (
        exact_object(value, {"conventional", "bounded"})
        and validate_estimate(value["conventional"])
        and validate_estimate(value["bounded"])
    )


def validate_observed(value):
    keys = {
        "peak_resident_bytes",
        "scratch_high_water_bytes",
        "wall_time_millis",
    }
    return exact_object(value, keys) and all(uint64(value[key]) for key in keys)


def validate_release(value):
    keys = {
        "guard_version",
        "guard_source_identity",
        "engine_source_identity",
        "engine_artifact_sha256",
        "release_identity",
        "compatibility_profile",
        "qualification",
    }
    return (
        exact_object(value, keys)
        and safe_release_identity(value["guard_version"])
        and safe_release_identity(value["guard_source_identity"])
        and safe_release_identity(value["engine_source_identity"])
        and lower_hex_digest(value["engine_artifact_sha256"])
        and safe_release_identity(value["release_identity"])
        and value["compatibility_profile"] == COMPATIBILITY_PROFILE
        and safe_release_identity(value["qualification"])
    )


def validate_artifact(value):
    return (
        exact_object(value, {"relative_path", "sha256"})
        and safe_relative_path(value["relative_path"])
        and lower_hex_digest(value["sha256"])
    )


def validate_job_result(value, expected_status):
    keys = {
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
    if (
        not exact_object(value, keys)
        or value["schema_version"] != 1
        or type(value["schema_version"]) is not int
        or value["status"] != expected_status
        or value["requested_mode"] not in {"auto", "conventional", "bounded"}
        or value["selected_mode"] not in {"conventional", "bounded"}
        or not validate_estimates(value["estimates"])
        or not validate_release(value["release"])
        or type(value["resumable"]) is not bool
    ):
        return False
    if (
        value["requested_mode"] == "conventional"
        and value["selected_mode"] != "conventional"
        or value["requested_mode"] == "bounded"
        and value["selected_mode"] != "bounded"
    ):
        return False
    observed = value["observed_resources"]
    proof = value["proof"]
    reason = value["reason"]
    checkpoint = value["checkpoint_relative_path"]
    if observed is not None and not validate_observed(observed):
        return False
    if proof is not None and not validate_artifact(proof):
        return False
    if reason is not None and not validate_reason(reason):
        return False
    if checkpoint is not None and not safe_relative_path(checkpoint):
        return False

    if expected_status == "succeeded":
        return (
            observed is not None
            and observed["peak_resident_bytes"] > 0
            and observed["wall_time_millis"] > 0
            and proof is not None
            and value["verifier_outcome"] == "accepted"
            and reason is None
            and value["resumable"] is False
            and checkpoint is None
        )
    if expected_status == "interrupted":
        return (
            value["selected_mode"] == "bounded"
            and observed is None
            and proof is None
            and value["verifier_outcome"] == "not_run"
            and reason is not None
            and reason["code"] == "interrupted_resumable"
            and value["resumable"] is True
            and checkpoint is not None
        )
    return False


def validate_error(value, expected_exit):
    if not exact_object(
        value,
        {"schema_version", "engine_release_identity", "ok", "error"},
    ):
        return False
    error = value["error"]
    if not exact_object(
        error,
        {"class", "exit_code", "reason", "resumable", "checkpoint_present"},
    ):
        return False
    try:
        expected_exit = int(expected_exit)
    except ValueError:
        return False
    reason = error["reason"]
    return (
        value["schema_version"] == 1
        and type(value["schema_version"]) is int
        and value["ok"] is False
        and safe_release_identity(value["engine_release_identity"])
        and validate_reason(reason)
        and error["class"] == reason["class"]
        and uint64(error["exit_code"])
        and error["exit_code"] == CLASS_EXIT[error["class"]]
        and error["exit_code"] == expected_exit
        and type(error["resumable"]) is bool
        and type(error["checkpoint_present"]) is bool
        and (not error["resumable"] or error["checkpoint_present"])
    )


def main():
    if len(sys.argv) != 4:
        return 2
    kind, expectation, path = sys.argv[1:]
    try:
        value = load_one(path)
        valid = (
            validate_job_result(value, expectation)
            if kind == "job-result"
            else validate_error(value, expectation)
            if kind == "error-envelope"
            else False
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        valid = False
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
