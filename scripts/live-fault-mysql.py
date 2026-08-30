#!/usr/bin/env python3
"""Deterministic hostile MySQL peer for live component acceptance."""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
from pathlib import Path


CAPABILITIES = 0x801FF7DF
AUTH_DATA = b'gve\'V,rQ"{v/;mYHB8.;'
EOF_PACKET = b"\xfe\x00\x00\x02\x00"
AUTH_OK = b"\x00\x00\x00\x02\x00\x00\x00"


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
    return header[3], read_exact(connection, int.from_bytes(header[:3], "little"))


def greeting() -> bytes:
    payload = bytearray(b"\x0a5.7.32\x00")
    payload.extend(struct.pack("<I", 19))
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


def column(vendor_type: int) -> bytes:
    output = bytearray()
    for label in (b"def", b"app", b"fault", b"fault", b"value", b"value"):
        output.append(len(label))
        output.extend(label)
    output.append(0x0C)
    output.extend(struct.pack("<H", 63))
    output.extend(struct.pack("<I", 64))
    output.append(vendor_type)
    output.extend(struct.pack("<H", 0))
    output.extend(b"\x00\x00\x00")
    return bytes(output)


def send_row_result(connection: socket.socket, vendor_type: int, value: bytes) -> None:
    connection.sendall(packet(1, b"\x01"))
    connection.sendall(packet(2, column(vendor_type)))
    connection.sendall(packet(3, EOF_PACKET))
    connection.sendall(packet(4, bytes([len(value)]) + value))
    connection.sendall(packet(5, EOF_PACKET))


def authenticate(connection: socket.socket) -> None:
    connection.settimeout(5)
    connection.sendall(packet(0, greeting()))
    sequence, response = read_packet(connection)
    if sequence != 1 or not response:
        raise AssertionError("invalid client handshake response")
    connection.sendall(packet(2, AUTH_OK))


def read_query(connection: socket.socket) -> str:
    sequence, payload = read_packet(connection)
    if sequence != 0 or not payload or payload[0] != 3:
        raise AssertionError("expected sequence-zero COM_QUERY")
    return payload[1:].decode("utf-8")


def require_eof(connection: socket.socket) -> None:
    connection.settimeout(5)
    if connection.recv(1):
        raise AssertionError("client sent data after terminal result")


def serve_typed(listener: socket.socket) -> dict[str, object]:
    expected = [
        "SELECT malformed_metadata",
        "SELECT invalid_integer",
        "SELECT oversized_packet",
    ]
    observed = []
    for index, statement in enumerate(expected):
        connection, _address = listener.accept()
        with connection:
            authenticate(connection)
            actual = read_query(connection)
            observed.append(actual)
            if actual != statement:
                raise AssertionError(f"query differs: {actual!r} != {statement!r}")
            if index == 0:
                send_row_result(connection, 243, b"x")
            elif index == 1:
                send_row_result(connection, 8, b"not-integer")
            else:
                connection.sendall((1_048_577).to_bytes(3, "little") + b"\x01")
            require_eof(connection)
    listener.settimeout(1)
    try:
        extra, _address = listener.accept()
    except TimeoutError:
        extra = None
    if extra is not None:
        extra.close()
        raise AssertionError("client opened an unexpected fourth connection")
    return {"connections": 3, "queries": observed, "terminal_eof": 3}


def serve_transport(listener: socket.socket) -> dict[str, object]:
    connection, _address = listener.accept()
    with connection:
        authenticate(connection)
        statement = read_query(connection)
        if statement != "SELECT socket_loss":
            raise AssertionError(f"query differs: {statement!r}")
    listener.settimeout(2)
    try:
        extra, _address = listener.accept()
    except TimeoutError:
        extra = None
    if extra is not None:
        extra.close()
        raise AssertionError("client reconnected after socket loss")
    return {"connections": 1, "queries": [statement], "reconnects": 0}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("typed", "transport"))
    parser.add_argument("ready_file", type=Path)
    parser.add_argument("evidence_file", type=Path)
    arguments = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        listener.settimeout(15)
        arguments.ready_file.write_text(str(listener.getsockname()[1]), encoding="ascii")
        if arguments.mode == "typed":
            evidence = serve_typed(listener)
        else:
            evidence = serve_transport(listener)
    arguments.evidence_file.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # noqa: BLE001 - fixture must expose every failure
        print(f"live fault peer failed: {error}", file=sys.stderr)
        raise
