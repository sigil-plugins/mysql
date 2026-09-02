#!/usr/bin/env python3
"""Prove optimized MySQL auth digest wipes remain on the exported connect path."""

from __future__ import annotations

from collections import deque
import os
from pathlib import Path
import re
import subprocess
import sys


CONNECT_EXPORT = "sigil:sql/driver@0.2.0#connect"
EXPECTED_DIGEST_WIPE_ORDERS = {
    (20, 20, 20, 32, 32, 32),
    (32, 32, 32, 20, 20, 20),
}


def abort(message: str) -> None:
    raise SystemExit(f"optimized Wasm zeroization check failed: {message}")


def direct_calls(body: list[str]) -> list[int]:
    calls: list[int] = []
    for line in body:
        match = re.fullmatch(r"call (\d+)", line.strip())
        if match:
            calls.append(int(match.group(1)))
    return calls


def main() -> None:
    if len(sys.argv) != 2:
        abort("usage: check-release-zeroize.py CORE_WASM")

    core_wasm = Path(sys.argv[1])
    if not core_wasm.is_file() or core_wasm.is_symlink():
        abort(f"core module is not an ordinary file: {core_wasm}")

    wasm_tools = os.environ.get("WASM_TOOLS", "wasm-tools")
    printed = subprocess.run(
        [wasm_tools, "print", str(core_wasm)],
        check=False,
        capture_output=True,
        text=True,
    )
    if printed.returncode != 0:
        abort(f"wasm-tools print failed: {printed.stderr.strip()}")
    lines = printed.stdout.splitlines()

    functions: dict[int, list[str]] = {}
    current_index: int | None = None
    current_body: list[str] = []
    for line in lines:
        header = re.match(r"^  \(func \(;([0-9]+);\)", line)
        if current_index is None and header:
            current_index = int(header.group(1))
            current_body = [line]
            continue
        if current_index is not None:
            current_body.append(line)
            if line == "  )":
                functions[current_index] = current_body
                current_index = None
                current_body = []
    if current_index is not None or not functions:
        abort("could not parse defined functions from wasm-tools output")

    connect_pattern = re.compile(
        rf'^  \(export "{re.escape(CONNECT_EXPORT)}" \(func ([0-9]+)\)\)$'
    )
    connect_exports = [
        int(match.group(1))
        for line in lines
        if (match := connect_pattern.fullmatch(line))
    ]
    if len(connect_exports) != 1:
        abort(f"expected one {CONNECT_EXPORT} export, found {len(connect_exports)}")

    call_graph = {index: set(direct_calls(body)) for index, body in functions.items()}
    reachable: set[int] = set()
    pending = deque(connect_exports)
    while pending:
        index = pending.popleft()
        if index in reachable:
            continue
        reachable.add(index)
        pending.extend(call_graph.get(index, ()))

    candidates: list[tuple[int, int, int]] = []
    for wipe_index, wipe_body in functions.items():
        header = wipe_body[0]
        stripped = [line.strip() for line in wipe_body]
        if "(param i32 i32)" not in header:
            continue
        loop_count = sum(line.startswith("loop ;; label = @") for line in stripped)
        if stripped.count("i32.store8") != 1 or loop_count != 1:
            continue
        if "i32.const 0" not in stripped:
            continue

        wipe_calls = direct_calls(wipe_body)
        if len(wipe_calls) != 1:
            continue
        barrier_index = wipe_calls[0]
        barrier_body = functions.get(barrier_index)
        if barrier_body is None:
            continue
        barrier_ops = [line.strip() for line in barrier_body[1:-1] if line.strip()]
        if barrier_ops != ["local.get 0", "i32.load8_u", "drop"]:
            continue
        if stripped.index("i32.store8") > stripped.index(f"call {barrier_index}"):
            continue

        for caller_index in reachable:
            caller = functions.get(caller_index)
            if caller is None:
                continue
            lengths: list[int] = []
            for position, line in enumerate(caller):
                if line.strip() != f"call {wipe_index}":
                    continue
                if position == 0:
                    abort("zeroize call has no length operand")
                length = re.fullmatch(r"i32.const ([0-9]+)", caller[position - 1].strip())
                if length is None:
                    # Other reachable secret buffers (for example, the
                    # host-supplied entropy Vec) also use this wipe helper but
                    # have a runtime length. They are not digest candidates;
                    # the exact six fixed digest wipes remain required below.
                    continue
                lengths.append(int(length.group(1)))
            expected_count = len(next(iter(EXPECTED_DIGEST_WIPE_ORDERS)))
            for start in range(len(lengths) - expected_count + 1):
                if tuple(lengths[start : start + expected_count]) in EXPECTED_DIGEST_WIPE_ORDERS:
                    candidates.append((wipe_index, barrier_index, caller_index))

    if len(candidates) != 1:
        abort(
            "expected one exported-connect path with retained 3x20-byte and "
            f"3x32-byte volatile wipes, found {len(candidates)}"
        )

    wipe_index, barrier_index, caller_index = candidates[0]
    print(
        "optimized Wasm retains six password-digest wipes on exported connect "
        f"(caller={caller_index}, wipe={wipe_index}, barrier={barrier_index})"
    )


if __name__ == "__main__":
    main()
