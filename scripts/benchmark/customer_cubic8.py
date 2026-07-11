#!/usr/bin/env python3
"""Generate the deterministic customer_cubic8 AIR, trace, and public inputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct


MODULUS = 18446744069414584321
PROFILE = "tinyzkp-p3-goldilocks-v1"
WIDTH = 8


def build_air() -> dict[str, object]:
    expressions: list[dict[str, object]] = []
    constraints: list[dict[str, object]] = []

    def add(expression: dict[str, object]) -> int:
        expressions.append(expression)
        return len(expressions) - 1

    for column in range(WIDTH):
        current = add({"op": "current", "column": column})
        public = add({"op": "public", "index": column})
        difference = add({"op": "sub", "left": current, "right": public})
        constraints.append({"kind": "first_row", "expression": difference})

        current = add({"op": "current", "column": column})
        square = add({"op": "mul", "left": current, "right": current})
        cube = add({"op": "mul", "left": square, "right": current})
        neighbor = add({"op": "current", "column": (column + 1) % WIDTH})
        expected = add({"op": "add", "left": cube, "right": neighbor})
        following = add({"op": "next", "column": column})
        difference = add({"op": "sub", "left": following, "right": expected})
        constraints.append({"kind": "transition", "expression": difference})

        current = add({"op": "current", "column": column})
        public = add({"op": "public", "index": WIDTH + column})
        difference = add({"op": "sub", "left": current, "right": public})
        constraints.append({"kind": "last_row", "expression": difference})

    return {
        "schema_version": 1,
        "backend": "plonky3",
        "profile": PROFILE,
        "field": "goldilocks",
        "expected_verifier": "p3_uni_stark_0.6.1",
        "trace_width": WIDTH,
        "public_inputs": [
            *({"name": f"initial_{index}"} for index in range(WIDTH)),
            *({"name": f"final_{index}"} for index in range(WIDTH)),
        ],
        "expressions": expressions,
        "constraints": constraints,
    }


def write_trace(path: Path, rows: int, initial: list[int]) -> list[int]:
    if rows < 1024 or rows > 1 << 24 or rows & (rows - 1):
        raise ValueError("rows must be a supported power of two")
    values = initial.copy()
    last = values.copy()
    with path.open("wb") as handle:
        for _ in range(rows):
            last = values.copy()
            handle.write(struct.pack("<8Q", *values))
            values = [
                (values[column] ** 3 + values[(column + 1) % WIDTH]) % MODULUS
                for column in range(WIDTH)
            ]
    return last


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    initial = list(range(1, WIDTH + 1))
    air = build_air()
    write_json(args.output / "air.json", air)
    final = write_trace(args.output / "trace.bin", args.rows, initial)
    write_json(
        args.output / "public-inputs.template.json",
        {"schema_version": 1, "air_digest_hex": "FILLED_AFTER_VALIDATE_AIR", "values": initial + final},
    )


if __name__ == "__main__":
    main()
