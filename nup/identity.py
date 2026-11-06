"""Package identity extracted from dump files: NPDM program ids and NSO build ids.

Switch 2 NPDMs carry program ids in the 0400… namespace while NCM title ids
use 0100… (see SPEC_ISSUES in layout), so ids are normalized on read.
"""

import struct

from .errors import NupError

S2_NAMESPACE_MASK = 0x00FF_FFFF_FFFF_FFFF
S1_NAMESPACE_BITS = 0x0100_0000_0000_0000
BUILD_ID_OFFSET = 0x40
BUILD_ID_SIZE = 0x20
NPDM_HEADER_MAGIC = b"META"


def normalize_title_id(program_id: int) -> int:
    if program_id >> 56 == 0x04:
        return (program_id & S2_NAMESPACE_MASK) | S1_NAMESPACE_BITS
    return program_id


def parse_npdm_program_id(data: bytes) -> int | None:
    offset = data.find(b"ACI0")
    if offset < 0 or offset + 0x18 > len(data):
        return None
    program_id, = struct.unpack_from("<Q", data, offset + 0x10)
    if program_id == 0:
        return None
    return normalize_title_id(program_id)


def read_npdm_program_id(fs_path: str) -> int | None:
    try:
        with open(fs_path, "rb") as handle:
            data = handle.read()
    except OSError:
        return None
    if data[:4] != NPDM_HEADER_MAGIC:
        return None
    return parse_npdm_program_id(data)


def read_build_id(fs_path: str) -> bytes | None:
    """NSO0/NRO0 module id: bytes 0x40..0x60 of the exefs `main` binary."""
    try:
        with open(fs_path, "rb") as handle:
            head = handle.read(BUILD_ID_OFFSET + BUILD_ID_SIZE)
    except OSError:
        return None
    if len(head) < BUILD_ID_OFFSET + BUILD_ID_SIZE:
        return None
    if head[:4] != b"NSO0" and head[0x10:0x14] != b"NRO0":
        return None
    return head[BUILD_ID_OFFSET : BUILD_ID_OFFSET + BUILD_ID_SIZE]


def exefs_file(content_dir: str, name: str) -> str | None:
    for candidate in (f"{content_dir}/exefs/{name}", f"{content_dir}/{name}"):
        try:
            with open(candidate, "rb"):
                return candidate
        except OSError:
            continue
    return None


def resolve_identity(content_dir: str) -> tuple[int | None, bytes | None]:
    npdm_path = exefs_file(content_dir, "main.npdm")
    program_id = read_npdm_program_id(npdm_path) if npdm_path else None
    main_path = exefs_file(content_dir, "main")
    build_id = read_build_id(main_path) if main_path else None
    return program_id, build_id


def require_title_id(content_dir: str, override: int | None) -> int:
    if override is not None:
        return override
    program_id, _ = resolve_identity(content_dir)
    if program_id is None:
        raise NupError(
            f"{content_dir!r} has no exefs/main.npdm program id; pass --title-id"
        )
    return program_id
