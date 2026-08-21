#!/usr/bin/env python3
"""Emit Sigil's canonical two-member plugin archive."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import tomllib

BLOCK = 512


def octal_field(width: int, value: int) -> bytes:
    digits = f"{value:o}".encode("ascii")
    if len(digits) + 1 > width:
        raise ValueError("tar numeric field cannot represent input")
    return b"0" * (width - len(digits) - 1) + digits + b"\0"


def split_ustar_path(raw: str) -> tuple[bytes, bytes]:
    encoded = raw.encode("utf-8")
    if len(encoded) <= 100:
        return b"", encoded
    for index in range(len(raw), 0, -1):
        if raw[index - 1] != "/":
            continue
        prefix = raw[: index - 1].encode("utf-8")
        name = raw[index:].encode("utf-8")
        if len(prefix) <= 155 and len(name) <= 100:
            return prefix, name
    raise ValueError("package path cannot be represented by POSIX ustar")


def header(raw_path: str, size: int) -> bytes:
    path = PurePosixPath(raw_path)
    if path.is_absolute() or not path.parts or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise ValueError("component path is not portable")
    prefix, name = split_ustar_path(raw_path)
    block = bytearray(BLOCK)
    block[: len(name)] = name
    block[345 : 345 + len(prefix)] = prefix
    block[100:108] = octal_field(8, 0o644)
    block[108:116] = octal_field(8, 0)
    block[116:124] = octal_field(8, 0)
    block[124:136] = octal_field(12, size)
    block[136:148] = octal_field(12, 0)
    block[148:156] = b"        "
    block[156] = ord("0")
    block[257:263] = b"ustar\0"
    block[263:265] = b"00"
    checksum = f"{sum(block):06o}".encode("ascii")
    if len(checksum) != 6:
        raise ValueError("tar checksum cannot be represented")
    block[148:156] = checksum + b"\0 "
    return bytes(block)


def write_member(stream, archive_path: str, source: Path) -> None:
    size = source.stat().st_size
    stream.write(header(archive_path, size))
    copied = 0
    with source.open("rb") as handle:
        while chunk := handle.read(16 * 1024):
            stream.write(chunk)
            copied += len(chunk)
    if copied != size:
        raise RuntimeError("plugin input changed while packing")
    stream.write(b"\0" * ((BLOCK - size % BLOCK) % BLOCK))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    manifest = args.manifest
    if manifest.name != "plugin.toml" or not manifest.is_file() or manifest.is_symlink():
        raise SystemExit("manifest must be an ordinary plugin.toml")
    with manifest.open("rb") as handle:
        parsed = tomllib.load(handle)
    name = parsed.get("name")
    version = parsed.get("version")
    component_raw = parsed.get("component", {}).get("file")
    if not isinstance(name, str) or re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name) is None:
        raise SystemExit("manifest plugin name is not canonical")
    if not isinstance(version, str) or re.fullmatch(r"[0-9A-Za-z.+-]+", version) is None:
        raise SystemExit("manifest version is not filename-safe")
    if not isinstance(component_raw, str):
        raise SystemExit("manifest component file is missing")
    component_path = PurePosixPath(component_raw)
    if (
        component_path.is_absolute()
        or component_path.as_posix() != component_raw
        or any(part in {"", ".", ".."} for part in component_path.parts)
    ):
        raise SystemExit("manifest component path is not portable")
    component = manifest.parent.joinpath(*component_path.parts)
    if not component.is_file() or component.is_symlink():
        raise SystemExit("manifest component must be an ordinary file")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    output = args.output_dir / f"{name}-{version}.sigil-plugin.tar.zst"
    temporary = tempfile.NamedTemporaryFile(
        prefix="plugin-pack-", dir=args.output_dir, delete=False
    )
    temporary_path = Path(temporary.name)
    try:
        process = subprocess.Popen(
            [os.environ.get("ZSTD", "zstd"), "-q", "-10", "--check", "-c"],
            stdin=subprocess.PIPE,
            stdout=temporary,
        )
        if process.stdin is None:
            raise RuntimeError("cannot open zstd input")
        try:
            write_member(process.stdin, "plugin.toml", manifest)
            write_member(process.stdin, component_raw, component)
            process.stdin.write(b"\0" * (2 * BLOCK))
        finally:
            process.stdin.close()
        if process.wait() != 0:
            raise RuntimeError("zstd failed")
        temporary.flush()
        os.fsync(temporary.fileno())
        temporary.close()
        os.replace(temporary_path, output)
    except BaseException:
        temporary.close()
        temporary_path.unlink(missing_ok=True)
        raise

    with output.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    checksum = args.output_dir / "SHA256SUMS"
    checksum.write_text(f"{digest}  {output.name}\n", encoding="ascii")
    print(output)
    print(checksum)


if __name__ == "__main__":
    main()
