import hashlib
import json
from pathlib import Path

import pytest
import smoke_engine_release_artifacts as smoke


RELEASE_SHA = "a" * 40
RELEASE_REF = "backend-v1.0.0"
CONFIG_DIGEST = "sha256:" + "c" * 64
MANIFEST_DIGEST = "sha256:" + "d" * 64
CONTAINER_ID = "e" * 64


def release_value():
    return {
        "service": "cli",
        "package_version": "0.1.0",
        "release_sha": RELEASE_SHA,
        "release_ref": RELEASE_REF,
        "backend": "plonky3",
        "plonky3_version": "0.6.1",
        "compatibility_profile": "tinyzkp-p3-goldilocks-v1",
        "dependency_lock_sha256": "b" * 64,
    }


def release_bytes(value=None):
    return (
        json.dumps(value or release_value(), indent=2, sort_keys=True) + "\n"
    ).encode()


def write_inputs(root: Path):
    artifacts = root / "release-artifacts"
    artifacts.mkdir()
    engine = artifacts / "tinyzkp-engine-linux-x86_64"
    engine.write_bytes(b"engine")
    engine.chmod(0o755)
    engine_release = artifacts / "engine-release.json"
    engine_release.write_bytes(release_bytes())
    oci = artifacts / "tinyzkp-engine.oci.tar"
    oci.write_bytes(b"local-oci-archive")

    tools_dir = root / "tools"
    tools_dir.mkdir()
    skopeo = tools_dir / "skopeo"
    docker = tools_dir / "docker"
    for tool in (skopeo, docker):
        tool.write_text("#!/bin/sh\nexit 1\n")
        tool.chmod(0o755)
    return engine, engine_release, oci, smoke.RuntimeTools(skopeo, docker)


class FakeRunner:
    def __init__(
        self,
        *,
        tools: smoke.RuntimeTools,
        engine: Path,
        output: bytes,
        network_mode: str = "none",
        mutate_engine: bool = False,
        report_tmpfs_mounts: bool = False,
    ):
        self.tools = tools
        self.engine = engine
        self.output = output
        self.network_mode = network_mode
        self.mutate_engine = mutate_engine
        self.report_tmpfs_mounts = report_tmpfs_mounts
        self.calls = []
        self.inspect_count = 0
        self.image_reference = None

    def result(self, stdout=b"", stderr=b""):
        return smoke.CommandResult(stdout=stdout, stderr=stderr)

    def container(self, *, after_run: bool):
        option = smoke.tmpfs_option()
        return {
            "Id": CONTAINER_ID,
            "Image": CONFIG_DIGEST,
            "Path": "/usr/local/bin/tinyzkp-engine",
            "Args": ["release"],
            "Config": {
                "User": "10001:10001",
                "Entrypoint": ["/usr/local/bin/tinyzkp-engine"],
                "Cmd": ["release"],
            },
            "HostConfig": {
                "NetworkMode": self.network_mode,
                "ReadonlyRootfs": True,
                "Privileged": False,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Binds": None,
                "Devices": [],
                "DeviceRequests": [],
                "PublishAllPorts": False,
                "PidMode": "",
                "IpcMode": "private",
                "UTSMode": "",
                "Memory": smoke.MEMORY_BYTES,
                "NanoCpus": smoke.NANO_CPUS,
                "PidsLimit": smoke.PIDS_LIMIT,
                "Tmpfs": {"/work": option, "/scratch": option},
            },
            "State": {
                "Status": "exited" if after_run else "created",
                "Running": False,
                "ExitCode": 0,
                "OOMKilled": False,
                "Error": "",
            },
            "Mounts": (
                [
                    {
                        "Type": "tmpfs",
                        "Source": "",
                        "Destination": "/work",
                        "RW": True,
                    },
                    {
                        "Type": "tmpfs",
                        "Source": "",
                        "Destination": "/scratch",
                        "RW": True,
                    },
                ]
                if after_run and self.report_tmpfs_mounts
                else []
            ),
        }

    def run(self, argv, *, env, cwd, timeout, check=True):
        argv = list(argv)
        self.calls.append(argv)
        assert "HC_RELEASE_SHA" not in env
        assert "HC_RELEASE_REF" not in env
        assert Path(env["HOME"]) == cwd
        if argv == [str(self.engine), "release"]:
            return self.result(self.output)
        if argv[0] == str(self.tools.skopeo.resolve()):
            self.image_reference = argv[-1].removeprefix("docker-daemon:")
            return self.result()

        docker_prefix = [
            str(self.tools.docker.resolve()),
            "--host",
            smoke.DOCKER_HOST,
        ]
        assert argv[:3] == docker_prefix
        command = argv[3:]
        if command[:2] == ["image", "inspect"]:
            image = {
                "Id": CONFIG_DIGEST,
                "Os": "linux",
                "Architecture": "amd64",
                "RepoTags": [self.image_reference],
                "Config": {
                    "User": "10001:10001",
                    "WorkingDir": "/work",
                    "Entrypoint": ["/usr/local/bin/tinyzkp-engine"],
                    "Cmd": ["--help"],
                },
            }
            return self.result(json.dumps([image]).encode())
        if command[0] == "create":
            return self.result((CONTAINER_ID + "\n").encode())
        if command[:2] == ["container", "inspect"]:
            self.inspect_count += 1
            return self.result(
                json.dumps([self.container(after_run=self.inspect_count == 2)]).encode()
            )
        if command[:2] == ["start", "--attach"]:
            if self.mutate_engine:
                self.engine.write_bytes(b"mutated-engine")
            return self.result(self.output)
        if command[:2] in (["container", "rm"], ["image", "rm"]):
            return self.result()
        raise AssertionError(f"unexpected fake command: {argv}")


def patch_static_identity(monkeypatch):
    def fake_oci_identity(path, *, release_sha, release_ref, expected_engine_sha256):
        assert path.is_file()
        assert release_sha == RELEASE_SHA
        assert release_ref == RELEASE_REF
        assert expected_engine_sha256 == hashlib.sha256(b"engine").hexdigest()
        return {
            "manifest_digest": MANIFEST_DIGEST,
            "config_digest": CONFIG_DIGEST,
            "platform": "linux/amd64",
            "entrypoint": ["/usr/local/bin/tinyzkp-engine"],
            "embedded_engine_sha256": expected_engine_sha256,
        }

    monkeypatch.setattr(smoke.identity, "oci_identity", fake_oci_identity)


def build(tmp_path, monkeypatch, *, output=None, network_mode="none"):
    patch_static_identity(monkeypatch)
    engine, engine_release, oci, tools = write_inputs(tmp_path)
    runner = FakeRunner(
        tools=tools,
        engine=engine,
        output=output if output is not None else release_bytes(),
        network_mode=network_mode,
    )
    report = smoke.build_report(
        root=tmp_path,
        release_sha=RELEASE_SHA,
        release_ref=RELEASE_REF,
        engine=engine,
        engine_release=engine_release,
        oci_archive=oci,
        checked_at="2026-01-01T00:00:00Z",
        runner=runner,
        tools=tools,
    )
    return report, runner


def test_runtime_report_binds_cli_oci_and_confined_execution(tmp_path, monkeypatch):
    report, runner = build(tmp_path, monkeypatch)

    assert set(report) == {
        "schema_version",
        "status",
        "release_sha",
        "release_ref",
        "checked_at",
        "claims",
        "artifacts",
        "release_identity",
        "executions",
        "runtime_policy",
        "binding",
    }
    assert report["status"] == "pass"
    assert report["claims"] == {"cli_smoke": True, "oci_smoke": True}
    assert report["release_identity"] == release_value()
    assert (
        report["artifacts"]["engine_cli"]["sha256"]
        == hashlib.sha256(b"engine").hexdigest()
    )
    assert (
        report["artifacts"]["engine_oci"]["sha256"]
        == hashlib.sha256(b"local-oci-archive").hexdigest()
    )
    assert report["artifacts"]["engine_oci"]["runtime_image_id"] == CONFIG_DIGEST
    assert report["runtime_policy"]["network_mode"] == "none"
    assert report["runtime_policy"]["user"] == "10001:10001"
    assert report["runtime_policy"]["privileged"] is False
    assert all(report["binding"].values())

    skopeo_call = next(call for call in runner.calls if call[0].endswith("skopeo"))
    assert any(value.startswith("oci-archive:") for value in skopeo_call)
    assert any(value.startswith("docker-daemon:") for value in skopeo_call)
    assert all(
        "http://" not in value and "https://" not in value for value in skopeo_call
    )
    create = next(call for call in runner.calls if "create" in call)
    assert "--pull=never" in create
    assert create[create.index("--network") + 1] == "none"
    assert create[create.index("--user") + 1] == "10001:10001"
    assert "--read-only" in create
    assert ["--cap-drop", "ALL"] == create[
        create.index("--cap-drop") : create.index("--cap-drop") + 2
    ]


def test_runtime_report_accepts_explicit_tmpfs_mount_inventory(tmp_path, monkeypatch):
    patch_static_identity(monkeypatch)
    engine, engine_release, oci, tools = write_inputs(tmp_path)
    runner = FakeRunner(
        tools=tools,
        engine=engine,
        output=release_bytes(),
        report_tmpfs_mounts=True,
    )
    report = smoke.build_report(
        root=tmp_path,
        release_sha=RELEASE_SHA,
        release_ref=RELEASE_REF,
        engine=engine,
        engine_release=engine_release,
        oci_archive=oci,
        runner=runner,
        tools=tools,
    )
    assert report["claims"]["oci_smoke"] is True


def test_runtime_report_rejects_semantically_equal_but_byte_skewed_output(
    tmp_path, monkeypatch
):
    compact = json.dumps(release_value(), sort_keys=True).encode()
    with pytest.raises(smoke.RuntimeSmokeError, match="release bytes differ"):
        build(tmp_path, monkeypatch, output=compact)


def test_runtime_report_rejects_release_identity_skew(tmp_path, monkeypatch):
    skewed = release_value()
    skewed["release_sha"] = "f" * 40
    with pytest.raises(smoke.RuntimeSmokeError, match="release-skewed"):
        build(tmp_path, monkeypatch, output=release_bytes(skewed))


def test_runtime_report_rejects_duplicate_release_keys():
    duplicate = release_bytes().rstrip()[:-1] + b',"service":"cli"}\n'
    with pytest.raises(smoke.RuntimeSmokeError, match="duplicate JSON key"):
        smoke.validate_release(
            duplicate,
            release_sha=RELEASE_SHA,
            release_ref=RELEASE_REF,
            label="duplicate",
        )


def test_runtime_report_inspects_and_rejects_network_policy_skew(tmp_path, monkeypatch):
    patch_static_identity(monkeypatch)
    engine, engine_release, oci, tools = write_inputs(tmp_path)
    runner = FakeRunner(
        tools=tools,
        engine=engine,
        output=release_bytes(),
        network_mode="bridge",
    )
    with pytest.raises(smoke.RuntimeSmokeError, match="confinement policy"):
        smoke.build_report(
            root=tmp_path,
            release_sha=RELEASE_SHA,
            release_ref=RELEASE_REF,
            engine=engine,
            engine_release=engine_release,
            oci_archive=oci,
            runner=runner,
            tools=tools,
        )
    assert any(call[3:5] == ["container", "rm"] for call in runner.calls)
    assert any(call[3:5] == ["image", "rm"] for call in runner.calls)


def test_runtime_report_rejects_writable_cli(tmp_path, monkeypatch):
    patch_static_identity(monkeypatch)
    engine, engine_release, oci, tools = write_inputs(tmp_path)
    engine.chmod(0o775)
    with pytest.raises(smoke.RuntimeSmokeError, match="group/world writable"):
        smoke.build_report(
            root=tmp_path,
            release_sha=RELEASE_SHA,
            release_ref=RELEASE_REF,
            engine=engine,
            engine_release=engine_release,
            oci_archive=oci,
            runner=FakeRunner(tools=tools, engine=engine, output=release_bytes()),
            tools=tools,
        )


def test_runtime_report_rejects_artifact_mutation_during_execution(
    tmp_path, monkeypatch
):
    patch_static_identity(monkeypatch)
    engine, engine_release, oci, tools = write_inputs(tmp_path)
    runner = FakeRunner(
        tools=tools,
        engine=engine,
        output=release_bytes(),
        mutate_engine=True,
    )
    with pytest.raises(smoke.RuntimeSmokeError, match="changed during"):
        smoke.build_report(
            root=tmp_path,
            release_sha=RELEASE_SHA,
            release_ref=RELEASE_REF,
            engine=engine,
            engine_release=engine_release,
            oci_archive=oci,
            runner=runner,
            tools=tools,
        )
