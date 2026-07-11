# Billing runtime supply-chain procedure

The recovery billing service supports exactly one host dependency profile:

- Debian 12 (`ID=debian`, `VERSION_ID=12`)
- Linux `x86_64`
- `/usr/bin/python3`, CPython 3.11, `cp311`
- `manylinux2014_x86_64` wheels

Ubuntu, ARM, `/usr/local` Python, CPython 3.10, and CPython 3.12 are not
compatible profiles. A dependency update or target change requires a new
profile ID, lock, wheel manifest, review, and release evidence.

## Dependency artifacts

`requirements.txt` contains exact direct roots. `requirements.lock` contains
the exact active transitive closure, including test dependencies used by the
production preflight. `requirements-bootstrap.lock` authorizes one pip wheel
that is loaded from `PYTHONPATH` during installation but is never installed in
the runtime. `wheelhouse-manifest.json` binds every expected filename, package
name, version, byte size, and SHA-256 hash.

Build the wheelhouse on a disposable networked build machine, never on the
production host:

```sh
python3 billing/runtime_lock.py verify-metadata
python3 billing/runtime_lock.py download --output /secure-build/tinyzkp-wheelhouse
python3 billing/runtime_lock.py verify-wheelhouse \
  --wheelhouse /secure-build/tinyzkp-wheelhouse
```

The download is exact-hash constrained. Verification opens each file with
`O_NOFOLLOW`, hashes the opened descriptor, inspects the wheel from those same
bytes, rejects path traversal, symlinks and `.pth` startup hooks, checks target
tags and embedded name/version metadata, evaluates active PEP 508 markers and
extras for the frozen target, and proves the locked packages are exactly the
reachable dependency closure.

After independent byte/hash review, copy only the manifest-listed wheel files
to `/var/lib/tinyzkp-runtime/wheelhouse`. The directory must be root-owned mode
`0700`; every wheel must be a root-owned, single-link, non-writable regular
file. No index, source distribution, compiler, or network access is used by
`install_billing_runtime.sh`.

## Host runtime provenance

Wheel hashes do not authenticate `/usr/bin/python3.11`, the standard library,
the dynamic loader, or system shared libraries. The committed
`host-runtime-provenance.json` therefore starts with `status: unconfigured`,
and the installer fails before reading the bootstrap wheel while that status
remains.

On the fixed Debian 12 host, capture candidate evidence with the exact system
interpreter:

```sh
sudo /usr/bin/python3 billing/runtime_lock.py capture-host-provenance \
  --output /root/tinyzkp-host-runtime.candidate.json
```

The capture inventories every regular file under `/usr/lib/python3.11`, the
real interpreter, `/usr/bin/bash`, `/usr/bin/ldd`, `/usr/lib/os-release`, and
the recursively resolved shared-library dependency graph. Schema v2 binds each
file's root ownership, group, mode, unique-link count, content digest, and the
digest of its complete root-owned, non-writable, symlink-free parent chain.
Directory/file symlinks in the standard library, missing libraries, unexpected
file types, or inventory limits fail closed.

An independent reviewer must reproduce the capture, compare the fixed-host OS
package provenance, and review the file hashes. Only then may a source change
replace the committed unconfigured document with the captured fields, set
`status` to `reviewed`, and add a reviewer identity and UTC review timestamp.
The source commit is the authorization boundary; a locally edited or
unpublished production checkout cannot issue launch evidence.

Verify the reviewed inventory on the host before installation:

```sh
sudo /usr/bin/python3 billing/runtime_lock.py verify-host
sudo /usr/bin/python3 billing/runtime_lock.py verify-host-provenance
```

After the billing venv and pinned Node runtime are materialized, verify the
complete production runtime identity:

```sh
sudo /usr/bin/python3 billing/runtime_lock.py verify-production-runtime \
  --venv-root /var/lib/tinyzkp-runtime/billing-venv \
  --node-binary /var/lib/tinyzkp-runtime/node-v24.18.0-linux-x64/bin/node
```

This expands the identity to every venv byte, the exact pinned Node binary,
and the recursive ELF dependency closure. Production preflight recomputes and
binds the resulting `identity_sha256` both when evidence is issued and when it
is consumed.

## Installation and rollback

Run `deploy/hetzner/install_billing_runtime.sh` directly through its clean
shebang. The installer:

1. validates the host profile and reviewed host provenance;
2. verifies the lock and immutable wheelhouse;
3. creates a fixed root-private staging venv with `--without-pip`;
4. loads only the reviewed pip wheel, installs with no index, hashes only,
   binary wheels only, and bytecode compilation disabled;
5. requires the installed distribution set to equal the runtime lock;
6. removes activation scripts and venv symlinks, relocates entry-point paths,
   and freezes every resulting byte;
7. renames the previous runtime to a fixed rollback path, activates the
   staged runtime, and re-verifies imports and entry points at the final path;
8. restores the prior runtime on any error or signal.

Before any repository Python is executed, the installer also requires every
source parent and runtime metadata file to be root-owned and unavailable for
group/world writes. A nonblocking lock on the validated runtime-root directory
inode serializes staging, activation, rollback, and cleanup across concurrent
installer invocations.

A stale staging or rollback path is never removed automatically. It blocks the
next run for operator review.

Repository tests cover the transaction policy and pure-Python identity logic,
but they do not substitute for a privileged Debian integration drill. Before
production, exercise and retain raw evidence for two concurrent invocations,
failure and HUP/INT/TERM at venv creation, both rename boundaries, final-path
verification, successful rollback, and retry. Independently review that drill
with the host-provenance and fixed-host backup evidence.

The dependency and host-runtime checks address the Python host service only.
They do not replace container signing, release identity parity, backup restore
evidence, live containment canaries, or independent backend review.
