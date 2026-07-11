import io
import tarfile

import materialize_anchored_git as materializer


def package(payload=b"git-binary"):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:xz") as archive:
        info = tarfile.TarInfo("./usr/bin/git")
        info.size = len(payload)
        info.mode = 0o755
        archive.addfile(info, io.BytesIO(payload))
    member = stream.getvalue()
    name = b"data.tar.xz/".ljust(16)
    header = name + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"100644".ljust(8) + str(len(member)).encode().ljust(10) + b"`\n"
    return b"!<arch>\n" + header + member + (b"\n" if len(member) % 2 else b"")


def test_extracts_only_the_reviewed_git_member():
    assert materializer.extract_git(package()) == b"git-binary"

