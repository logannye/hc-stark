#!/usr/bin/env python3
"""Deterministic declarative AIR fixtures used by hosted beta evidence."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import struct
from typing import Callable


MODULUS = 18_446_744_069_414_584_321
PROFILE = "tinyzkp-p3-goldilocks-v1"


@dataclass(frozen=True)
class Fixture:
    name: str
    air: dict[str, object]
    initial_state: tuple[int, ...]
    row: Callable[[tuple[int, ...]], tuple[int, ...]]
    step: Callable[[tuple[int, ...]], tuple[int, ...]]
    public_values: Callable[[tuple[int, ...], tuple[int, ...]], list[int]]


class AirBuilder:
    def __init__(self, width: int, public_names: list[str]) -> None:
        self.width = width
        self.public_names = public_names
        self.expressions: list[dict[str, object]] = []
        self.constraints: list[dict[str, object]] = []

    def expression(self, op: str, **values: object) -> int:
        self.expressions.append({"op": op, **values})
        return len(self.expressions) - 1

    def current(self, column: int) -> int:
        return self.expression("current", column=column)

    def next(self, column: int) -> int:
        return self.expression("next", column=column)

    def public(self, index: int) -> int:
        return self.expression("public", index=index)

    def constant(self, value: int) -> int:
        return self.expression("constant", value=value)

    def binary(self, op: str, left: int, right: int) -> int:
        return self.expression(op, left=left, right=right)

    def constrain(self, kind: str, expression: int) -> None:
        self.constraints.append({"kind": kind, "expression": expression})

    def boundary(self, kind: str, column: int, public_index: int) -> None:
        self.constrain(
            kind,
            self.binary("sub", self.current(column), self.public(public_index)),
        )

    def package(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "backend": "plonky3",
            "profile": PROFILE,
            "field": "goldilocks",
            "expected_verifier": "p3_uni_stark_0.6.1",
            "trace_width": self.width,
            "public_inputs": [{"name": name} for name in self.public_names],
            "expressions": self.expressions,
            "constraints": self.constraints,
        }


def fibonacci() -> Fixture:
    builder = AirBuilder(2, ["initial_a", "initial_b", "final_a", "final_b"])
    builder.boundary("first_row", 0, 0)
    builder.boundary("first_row", 1, 1)
    builder.constrain(
        "transition",
        builder.binary("sub", builder.next(0), builder.current(1)),
    )
    builder.constrain(
        "transition",
        builder.binary(
            "sub",
            builder.next(1),
            builder.binary("add", builder.current(0), builder.current(1)),
        ),
    )
    builder.boundary("last_row", 0, 2)
    builder.boundary("last_row", 1, 3)

    def step(state: tuple[int, ...]) -> tuple[int, ...]:
        a, b = state
        return b, (a + b) % MODULUS

    return Fixture(
        "fibonacci",
        builder.package(),
        (1, 1),
        lambda state: state,
        step,
        lambda initial, final: [*initial, *final],
    )


def poseidon2_aux() -> Fixture:
    """An x^7 S-box recurrence lowered through x2/x3/x6 trace columns."""
    builder = AirBuilder(4, ["initial_x", "final_x"])
    builder.boundary("first_row", 0, 0)
    x = builder.current(0)
    x2 = builder.current(1)
    x3 = builder.current(2)
    x6 = builder.current(3)
    builder.constrain("transition", builder.binary("sub", x2, builder.binary("mul", x, x)))
    builder.constrain("transition", builder.binary("sub", x3, builder.binary("mul", x2, x)))
    builder.constrain("transition", builder.binary("sub", x6, builder.binary("mul", x3, x3)))
    next_x = builder.binary(
        "add", builder.binary("mul", x6, x), builder.constant(7)
    )
    builder.constrain("transition", builder.binary("sub", builder.next(0), next_x))
    builder.boundary("last_row", 0, 1)

    def row(state: tuple[int, ...]) -> tuple[int, ...]:
        (x_value,) = state
        square = x_value * x_value % MODULUS
        cube = square * x_value % MODULUS
        sixth = cube * cube % MODULUS
        return x_value, square, cube, sixth

    def step(state: tuple[int, ...]) -> tuple[int, ...]:
        x_value = state[0]
        return ((pow(x_value, 7, MODULUS) + 7) % MODULUS,)

    return Fixture(
        "poseidon2",
        builder.package(),
        (3,),
        row,
        step,
        lambda initial, final: [initial[0], final[0]],
    )


def customer_cubic8() -> Fixture:
    width = 8
    builder = AirBuilder(
        width,
        [*(f"initial_{index}" for index in range(width)), *(f"final_{index}" for index in range(width))],
    )
    for column in range(width):
        builder.boundary("first_row", column, column)
        current = builder.current(column)
        square = builder.binary("mul", current, current)
        cube = builder.binary("mul", square, current)
        expected = builder.binary("add", cube, builder.current((column + 1) % width))
        builder.constrain(
            "transition", builder.binary("sub", builder.next(column), expected)
        )
        builder.boundary("last_row", column, width + column)

    def step(state: tuple[int, ...]) -> tuple[int, ...]:
        return tuple(
            (state[column] ** 3 + state[(column + 1) % width]) % MODULUS
            for column in range(width)
        )

    return Fixture(
        "customer_cubic8",
        builder.package(),
        tuple(range(1, width + 1)),
        lambda state: state,
        step,
        lambda initial, final: [*initial, *final],
    )


def fixture(name: str) -> Fixture:
    fixtures = {
        "fibonacci": fibonacci,
        "poseidon2": poseidon2_aux,
        "customer_cubic8": customer_cubic8,
    }
    try:
        return fixtures[name]()
    except KeyError as error:
        raise ValueError(f"unsupported declarative fixture: {name}") from error


def write_trace(path: Path, selected: Fixture, rows: int) -> list[int]:
    if rows < 1024 or rows > 1 << 24 or rows & (rows - 1):
        raise ValueError("rows must be a power of two from 2^10 through 2^24")
    state = selected.initial_state
    final_row: tuple[int, ...] = ()
    with path.open("wb") as output:
        for _ in range(rows):
            final_row = selected.row(state)
            output.write(struct.pack(f"<{len(final_row)}Q", *final_row))
            state = selected.step(state)
    return selected.public_values(selected.initial_state, (final_row[0],) if selected.name == "poseidon2" else final_row)


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
