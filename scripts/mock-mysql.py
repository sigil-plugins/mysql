#!/usr/bin/env python3
"""Deterministic MySQL text-protocol peer for the real-component Lua gate."""

from __future__ import annotations

import argparse
import socket
import struct
import sys
from pathlib import Path


CAPABILITIES = 0x801FF7DF
AUTH_DATA = b'gve\'V,rQ"{v/;mYHB8.;'
EOF_PACKET = b"\xfe\x00\x00\x02\x00"
OK_AUTH = b"\x00\x00\x00\x02\x00\x00\x00"


def lenenc(value: int) -> bytes:
    if value <= 0xFA:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfc" + struct.pack("<H", value)
    if value <= 0xFFFFFF:
        return b"\xfd" + value.to_bytes(3, "little")
    return b"\xfe" + struct.pack("<Q", value)


def packet(sequence: int, payload: bytes) -> bytes:
    return len(payload).to_bytes(3, "little") + bytes([sequence]) + payload


def read_exact(connection: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        part = connection.recv(length - len(output))
        if not part:
            raise EOFError
        output.extend(part)
    return bytes(output)


def read_packet(connection: socket.socket) -> tuple[int, bytes]:
    header = read_exact(connection, 4)
    length = int.from_bytes(header[:3], "little")
    return header[3], read_exact(connection, length)


def greeting() -> bytes:
    payload = bytearray(b"\x0a5.7.32\x00")
    payload.extend(struct.pack("<I", 11))
    payload.extend(AUTH_DATA[:8])
    payload.append(0)
    payload.extend(struct.pack("<H", CAPABILITIES & 0xFFFF))
    payload.append(33)
    payload.extend(struct.pack("<H", 2))
    payload.extend(struct.pack("<H", CAPABILITIES >> 16))
    payload.append(21)
    payload.extend(bytes(10))
    payload.extend(AUTH_DATA[8:])
    payload.append(0)
    payload.extend(b"mysql_native_password\x00")
    return bytes(payload)


def ok(affected_rows: int, last_insert_id: int, warnings: int) -> bytes:
    return (
        b"\x00"
        + lenenc(affected_rows)
        + lenenc(last_insert_id)
        + struct.pack("<H", 2)
        + struct.pack("<H", warnings)
    )


def error() -> bytes:
    return b"\xff" + struct.pack("<H", 1201) + b"#HY000fixture rejection"


def column(vendor_type: int, flags: int, collation: int, name: bytes) -> bytes:
    labels = [b"def", b"app", b"conformance", b"conformance", name, name]
    output = bytearray()
    for label in labels:
        output.extend(lenenc(len(label)))
        output.extend(label)
    output.append(0x0C)
    output.extend(struct.pack("<H", collation))
    output.extend(struct.pack("<I", 64))
    output.append(vendor_type)
    output.extend(struct.pack("<H", flags))
    output.extend(b"\x00\x00\x00")
    return bytes(output)


def row(values: list[bytes | None]) -> bytes:
    output = bytearray()
    for value in values:
        if value is None:
            output.append(0xFB)
        else:
            output.extend(lenenc(len(value)))
            output.extend(value)
    return bytes(output)


def send_result(
    connection: socket.socket,
    columns: list[tuple[int, int, int, bytes]],
    values: list[bytes | None],
) -> None:
    connection.sendall(packet(1, lenenc(len(columns))))
    sequence = 2
    for definition in columns:
        connection.sendall(packet(sequence, column(*definition)))
        sequence += 1
    connection.sendall(packet(sequence, EOF_PACKET))
    sequence += 1
    connection.sendall(packet(sequence, row(values)))
    sequence += 1
    connection.sendall(packet(sequence, EOF_PACKET))


def send_signed_result(connection: socket.socket) -> None:
    send_result(connection, [(8, 0, 63, b"value")], [b"7"])


def send_typed_result(connection: socket.socket) -> None:
    columns = [
        (6, 0, 63, b"nothing"),
        (8, 0, 63, b"minimum"),
        (8, 0x20, 63, b"maximum"),
        (5, 0, 63, b"negative_zero"),
        (246, 0, 63, b"exact_decimal"),
        (253, 0, 45, b"text_value"),
        (252, 0, 63, b"byte_value"),
        (7, 0, 45, b"timestamp_value"),
    ]
    values = [
        None,
        b"-9223372036854775808",
        b"18446744073709551615",
        b"-0",
        b"001.2300",
        "snowman ☃".encode(),
        b"\x00\xff\x80",
        b"2026-08-30 12:34:56.000001",
    ]
    send_result(connection, columns, values)


FIRST_SESSION = [
    "CREATE TEMPORARY TABLE conformance(value BIGINT)",
    "INSERT INTO conformance VALUES (7)",
    "SELECT typed FROM conformance",
    "UPDATE fixture",
    "SELECT value FROM conformance",
    "ERROR server",
    "SELECT value FROM conformance",
]
SECOND_SESSION = ["SELECT value FROM conformance"]


def serve_session(connection: socket.socket, expected: list[str]) -> None:
    connection.settimeout(10)
    connection.sendall(packet(0, greeting()))
    sequence, response = read_packet(connection)
    if sequence != 1 or not response:
        raise AssertionError("invalid client handshake response")
    connection.sendall(packet(2, OK_AUTH))

    observed: list[str] = []
    while True:
        try:
            sequence, payload = read_packet(connection)
        except EOFError:
            break
        if sequence != 0 or not payload or payload[0] != 3:
            raise AssertionError("expected sequence-zero COM_QUERY")
        sql = payload[1:].decode("utf-8")
        observed.append(sql)
        if sql == FIRST_SESSION[0]:
            connection.sendall(packet(1, ok(0, 0, 0)))
        elif sql == FIRST_SESSION[1]:
            connection.sendall(packet(1, ok(1, 0, 2)))
        elif sql == FIRST_SESSION[2]:
            send_typed_result(connection)
        elif sql == FIRST_SESSION[3]:
            connection.sendall(packet(1, ok(2, 12, 3)))
        elif sql == "SELECT value FROM conformance":
            send_signed_result(connection)
        elif sql == "ERROR server":
            connection.sendall(packet(1, error()))
        else:
            raise AssertionError(f"unexpected SQL: {sql!r}")

    if observed != expected:
        raise AssertionError(f"statement trace differs: {observed!r} != {expected!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("ready_file", type=Path)
    arguments = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(20)
        arguments.ready_file.write_text(str(listener.getsockname()[1]), encoding="ascii")
        for expected in (FIRST_SESSION, SECOND_SESSION):
            connection, _address = listener.accept()
            with connection:
                serve_session(connection, expected)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # noqa: BLE001 - fixture must surface every failure
        print(f"mock MySQL failure: {error}", file=sys.stderr)
        raise
