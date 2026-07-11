#!/usr/bin/env python3
"""Build and test the Python SDK from the fixed offline evidence wheelhouse."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import venv

import verify_sdk_python_wheelhouse as wheelhouse


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = """
import runpy
import sys
wheel = sys.argv[1]
sys.path.insert(0, wheel)
sys.argv = [wheel, *sys.argv[2:]]
runpy.run_module("pip", run_name="__main__", alter_sys=True)
""".strip()


def _private_empty_directory(path: Path) -> Path:
    path = path.absolute()
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            details = os.lstat(current)
        except FileNotFoundError:
            os.mkdir(current, 0o700)
            details = os.lstat(current)
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
            raise ValueError("Python SDK work directory has unsafe ancestry")
    details = os.lstat(path)
    if details.st_uid != os.geteuid() or any(path.iterdir()):
        raise ValueError("Python SDK work directory must be empty and runner-owned")
    os.chmod(path, 0o700, follow_symlinks=False)
    return path


def _run(
    command: list[str], *, cwd: Path, environment: dict[str, str], pass_fds: tuple[int, ...] = ()
) -> None:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        pass_fds=pass_fds,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError(
            f"offline Python SDK command failed with status {completed.returncode}"
        )


def _capture(
    command: list[str], *, cwd: Path, environment: dict[str, str], pass_fds: tuple[int, ...] = ()
) -> bytes:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=pass_fds,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace")[-2000:]
        raise ValueError(f"offline Python SDK inspection failed: {detail}")
    return completed.stdout


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def materialize(*, wheelhouse_path: Path, work_dir: Path) -> dict[str, object]:
    wheelhouse.require_runtime_target()
    identity = wheelhouse.worktree_lock_identity(ROOT)
    sealed_raw = os.environ.get("TINYZKP_SEALED_PYTHON_WHEELS")
    sealed_fds: tuple[int, ...] = ()
    if sealed_raw:
        try:
            sealed = json.loads(sealed_raw)
        except json.JSONDecodeError as error:
            raise ValueError("sealed Python wheel descriptor manifest is malformed") from error
        if not isinstance(sealed, list):
            raise ValueError("sealed Python wheel descriptor manifest is malformed")
        wheelhouse.verify_sealed_wheelhouse(wheelhouse_path, identity, sealed)
        sealed_fds = tuple(int(record["fd"]) for record in sealed)
    else:
        wheelhouse.verify_wheelhouse(wheelhouse_path, identity)
    work_dir = _private_empty_directory(work_dir)
    home = work_dir / "home"
    temporary = work_dir / "tmp"
    distribution = work_dir / "dist"
    test_cwd = work_dir / "test-cwd"
    for path in (home, temporary, distribution, test_cwd):
        path.mkdir(mode=0o700)
    environment = {
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INPUT": "1",
        "PYTHONHASHSEED": "0",
        # ZIP timestamps cannot represent 1970; use the earliest safe DOS date.
        "SOURCE_DATE_EPOCH": "315532800",
        "TEMP": str(temporary),
        "TMP": str(temporary),
        "TMPDIR": str(temporary),
    }
    venv_path = work_dir / "python-venv"
    venv.EnvBuilder(
        system_site_packages=False,
        clear=False,
        symlinks=False,
        with_pip=False,
    ).create(venv_path)
    python = venv_path / "bin" / "python"
    details = os.lstat(python)
    if (
        stat.S_ISLNK(details.st_mode)
        or not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_mode & 0o111 == 0
    ):
        raise ValueError("offline Python SDK virtualenv interpreter is unsafe")
    source_python_sha256 = _file_sha256(Path(sys.executable))
    if _file_sha256(python) != source_python_sha256:
        raise ValueError("offline Python SDK virtualenv did not copy the anchored interpreter")
    pip_descriptor = next(
        item for item in identity["wheels"] if item["distribution"] == "pip"
    )
    pip_wheel = wheelhouse_path / str(pip_descriptor["filename"])
    requirements = ROOT / wheelhouse.REQUIREMENTS_PATH
    fixed_install = [
        str(python),
        "-I",
        "-c",
        BOOTSTRAP,
        str(pip_wheel),
        "--isolated",
        "install",
        "--no-index",
        "--no-cache-dir",
        "--require-hashes",
        "--only-binary=:all:",
        f"--find-links={wheelhouse_path}",
        "-r",
        str(requirements),
    ]
    _run(fixed_install, cwd=test_cwd, environment=environment, pass_fds=sealed_fds)
    _run(
        [
            str(python),
            "-I",
            "-m",
            "pip",
            "--isolated",
            "wheel",
            "--no-index",
            "--no-cache-dir",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(distribution),
            str(ROOT / "clients/python"),
        ],
        cwd=test_cwd,
        environment=environment,
        pass_fds=sealed_fds,
    )
    built = list(distribution.iterdir())
    if (
        len(built) != 1
        or not built[0].is_file()
        or built[0].is_symlink()
        or built[0].name != "tinyzkp-0.2.0.dev0-py3-none-any.whl"
    ):
        raise ValueError("Python SDK build did not emit the one expected wheel")
    built_payload = built[0].read_bytes()
    if not built_payload or len(built_payload) > 4 * 1024 * 1024:
        raise ValueError("Python SDK wheel has an invalid size")
    _run(
        [
            str(python),
            "-I",
            "-m",
            "pip",
            "--isolated",
            "install",
            "--no-index",
            "--no-cache-dir",
            "--no-deps",
            "--force-reinstall",
            str(built[0]),
        ],
        cwd=test_cwd,
        environment=environment,
        pass_fds=sealed_fds,
    )
    _run(
        [str(python), "-I", "-m", "pip", "--isolated", "check"],
        cwd=test_cwd,
        environment=environment,
        pass_fds=sealed_fds,
    )
    inventory_payload = _capture(
        [
            str(python),
            "-I",
            "-c",
            (
                "import importlib.metadata as m,json;"
                "print(json.dumps(sorted((d.metadata['Name'].lower().replace('_','-'),"
                "d.version) for d in m.distributions())))"
            ),
        ],
        cwd=test_cwd,
        environment=environment,
        pass_fds=sealed_fds,
    )
    try:
        inventory = json.loads(inventory_payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("Python SDK installed inventory is malformed") from error
    expected_inventory = sorted(
        [
            [str(item["distribution"]), str(item["version"])]
            for item in identity["wheels"]
        ]
        + [["tinyzkp", "0.2.0.dev0"]]
    )
    if inventory != expected_inventory:
        raise ValueError("Python SDK installed inventory differs from the lock")
    import_payload = _capture(
        [
            str(python),
            "-I",
            "-c",
            "import tinyzkp; print(tinyzkp.__file__)",
        ],
        cwd=test_cwd,
        environment=environment,
        pass_fds=sealed_fds,
    )
    try:
        imported = Path(import_payload.decode("utf-8").strip()).resolve()
        imported.relative_to(venv_path.resolve())
    except (UnicodeError, ValueError) as error:
        raise ValueError("Python SDK tests would import the source tree") from error
    _run(
        [
            str(python),
            "-I",
            "-m",
            "pytest",
            "--import-mode=importlib",
            str(ROOT / "clients/python/tests"),
            "-q",
        ],
        cwd=test_cwd,
        environment=environment,
        pass_fds=sealed_fds,
    )
    if _file_sha256(python) != source_python_sha256:
        raise ValueError("offline Python SDK interpreter changed during execution")
    result = {
        "schema_version": 1,
        "lock_sha256": identity["lock_sha256"],
        "wheel_set_sha256": identity["wheel_set_sha256"],
        "wheel_count": identity["wheel_count"],
        "sdk_wheel": built[0].name,
        "sdk_wheel_bytes": len(built_payload),
        "sdk_wheel_sha256": hashlib.sha256(built_payload).hexdigest(),
        "python_sha256": source_python_sha256,
        "installed_packages": expected_inventory,
    }
    print(
        "PASS TinyZKP locked Python SDK environment "
        f"({identity['wheel_count']} wheels, {identity['wheel_set_sha256']})"
    )
    return result


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = materialize(
            wheelhouse_path=args.wheelhouse.absolute(),
            work_dir=args.work_dir.absolute(),
        )
    except (OSError, StopIteration, ValueError) as error:
        print(f"locked Python SDK environment failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
