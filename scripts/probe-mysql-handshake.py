#!/usr/bin/env python3
"""Print bounded identity fields from a MySQL server's initial handshake."""

from __future__ import annotations

import argparse
import json
import socket


def read_exact(stream: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        part = stream.recv(length - len(output))
        if not part:
            raise EOFError("server closed during handshake")
        output.extend(part)
    return bytes(output)


def nul_terminated(payload: bytes, offset: int) -> tuple[bytes, int]:
    end = payload.find(b"\0", offset)
    if end < 0:
        raise ValueError("unterminated handshake field")
    return payload[offset:end], end + 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    arguments = parser.parse_args()

    with socket.create_connection((arguments.host, arguments.port), timeout=5) as stream:
        header = read_exact(stream, 4)
        length = int.from_bytes(header[:3], "little")
        if header[3] != 0 or length > 4096:
            raise ValueError("invalid handshake packet header")
        payload = read_exact(stream, length)

    if not payload or payload[0] != 10:
        raise ValueError("not a MySQL protocol 10 handshake")
    version_bytes, offset = nul_terminated(payload, 1)
    if offset + 4 + 8 + 1 + 2 > len(payload):
        raise ValueError("truncated handshake")
    offset += 4 + 8 + 1
    low = int.from_bytes(payload[offset : offset + 2], "little")
    offset += 2
    if offset == len(payload):
        capabilities = low
        plugin = ""
    else:
        if offset + 1 + 2 + 2 + 1 + 10 > len(payload):
            raise ValueError("truncated extended handshake")
        offset += 1 + 2
        high = int.from_bytes(payload[offset : offset + 2], "little")
        capabilities = low | (high << 16)
        offset += 2
        auth_length = payload[offset]
        offset += 1 + 10
        auth_tail = max(13, auth_length - 8)
        offset = min(len(payload), offset + auth_tail)
        plugin_bytes = payload[offset:].split(b"\0", 1)[0]
        plugin = plugin_bytes.decode("ascii")

    version = version_bytes.decode("ascii")
    print(
        json.dumps(
            {
                "auth_plugin": plugin,
                "capabilities": f"0x{capabilities:08x}",
                "server_version": version,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
