"""NUP v2 wire format: constants, structs, codecs, and content hashing.

Every byte-level rule of SPEC.md lives here.  Where the spec contradicted
itself or left a gap, the resolution is recorded in SPEC_ISSUES so the
choice is greppable from both the code and the spec text.  SPEC.md was
updated on 2026-11-06 to state these resolutions; the items still awaiting
a human call are its §10 items 5-8.
"""

from dataclasses import dataclass
import enum
import hashlib
import struct

from .errors import NupError

HFS0_MAGIC = b"HFS0"
HEADER_SIZE = 0x10
ENTRY_SIZE = 0x40
ALIGN = 0x200
PREFIX_HASH_SIZE = ALIGN

META_NAME = "meta.nup"
META_MAGIC = b"NUP\x02"
META_HEADER_SIZE = 0x40
PACKAGE_FIXED_SIZE = 0x38
DIGEST_SIZE = 0x20

DELETED_NAME = "@deleted"
ARTIFACT_SUFFIXES = (".listing",)

FLAG_DIFF = 0x01
KNOWN_FLAGS = FLAG_DIFF


class Kind(enum.IntEnum):
    BASE = 0
    UPDATE = 1
    ADDON = 2


KIND_SCOPE_PREFIX = {
    Kind.BASE: "base",
    Kind.UPDATE: "update/{version}",
    Kind.ADDON: "addon/{index}",
}


class Flags(enum.IntFlag):
    DIFF = FLAG_DIFF


class TlvType(enum.IntEnum):
    ICON = 0x0003
    DISPLAY_VERSION = 0x0004
    TITLE_NAME = 0x0005
    PUBLISHER = 0x0006
    LOCALIZED_TITLE = 0x0009
    LOCALIZED_ICON = 0x000A
    BUILD_ID = 0x000B
    SOURCE_DUMP = 0x000C


TEXT_TLV_TYPES = frozenset(
    {
        TlvType.DISPLAY_VERSION,
        TlvType.TITLE_NAME,
        TlvType.PUBLISHER,
        TlvType.BUILD_ID,
        TlvType.SOURCE_DUMP,
    }
)

TLV_MAX_LENGTH = 0xFFFF

CONTAINER_HEADER = struct.Struct("<4sIII")
CONTAINER_ENTRY = struct.Struct("<QQIIQ32s")
META_HEADER = struct.Struct("<4sHHIIQ32sI")
PACKAGE_RECORD = struct.Struct("<BBHQQIIQQQI")
assert CONTAINER_HEADER.size == HEADER_SIZE
assert CONTAINER_ENTRY.size == ENTRY_SIZE
assert META_HEADER.size == META_HEADER_SIZE - 4
assert PACKAGE_RECORD.size == PACKAGE_FIXED_SIZE

U64 = struct.Struct("<Q")


SPEC_ISSUES: dict[str, str] = {
    "string-table-alignment": (
        "SPEC §2 pads the string table 'out to a 0x200 boundary', which read "
        "literally aligns only the table itself; since 0x10 + 0x40*N is not "
        "generically 0x200-aligned, entry data would sit at unaligned file "
        "offsets and §1 rule 4's mmap claim would fail.  Resolution: the "
        "string table is padded so the data region STARTS on a 0x200 file "
        "boundary; string table size is stored padded."
    ),
    "meta-header-size": (
        "SPEC §3's listed meta fields end at 0x3C but the header size field "
        "is documented as '0x40 in v2.0'.  Resolution: writers emit 0x40 and "
        "zero bytes [0x3C, 0x40); readers accept header_size >= 0x3C and "
        "start package records at header_size."
    ),
    "content-hash-width": (
        "SPEC §6.2 defines the content hash as a SHA-256 digest but §3 gives "
        "the record fields only u64 slots ('0x1C u64 content hash').  "
        "Resolution: the record carries the first 8 bytes of the digest, "
        "little-endian (truncated_digest); the 256-bit digest exists only in "
        "the content-hash computation."
    ),
    "update-content-hash": (
        "SPEC §5.1 requires a diff's base content hash to equal the content "
        "hash of the tree it lands on, and §6.2 calls the content hash what "
        "an emulator compares 'after materializing a tree'.  A hash over an "
        "update's stored file table (diff entries only) cannot satisfy "
        "either.  Resolution: an update record's content hash is the "
        "materialized-state identity: the sorted (path, size, hash) set of "
        "base overlaid with the diff, minus @deleted.  A base package's "
        "content hash equals the hash of its own file table."
    ),
    "deleted-manifest-identity": (
        "SPEC §5.1 stores @deleted as a real scope entry but does not say "
        "whether it survives materialization.  Resolution: @deleted is "
        "consumed by the apply step, so it is excluded from the materialized "
        "content hash while remaining a hash-checked scope entry in the "
        "record's file table."
    ),
    "localized-tlv-framing": (
        "SPEC §3 describes the localized TLVs only as 'lang bytes + value', "
        "with no length framing.  Resolution: the v1 convention is carried "
        "over: u8 lang length, lang bytes, u16 value length, value bytes."
    ),
    "worked-example-counts": (
        "The draft §8 example said 1,306 changed / 3,452 total entries.  "
        "Measured on the real dumps: 2,145 added + 1,310 changed = 3,455 "
        "diff files, 41 removed, 3,457 total entries (meta + diff + "
        "@deleted).  The example's 2,145, its prose 1,310, and the 41 were "
        "exact; 1,306 was a typo and the totals followed from it.  SPEC.md "
        "§8 now carries the measured numbers."
    ),
    "switch2-title-id-namespace": (
        "SPEC §4 assumes dump title ids follow the console's 0100… "
        "convention, but Switch 2 NPDMs carry program ids in the 0400… "
        "namespace and update dumps carry the base application id in their "
        "ACI0 (no patch id anywhere).  Resolution: packers normalize 0400… "
        "to 0100… and derive patch/addon ids from the application id by "
        "the console's +0x800/+0x1000+index convention."
    ),
}


def truncated_digest(digest: bytes) -> int:
    """Content-hash identity as stored in a package record (SPEC_ISSUES)."""
    return int.from_bytes(digest[:8], "little")


def content_hash(rows: "list[FileRow]") -> bytes:
    """256-bit package identity over sorted file-table rows (SPEC §6.2)."""
    sha = hashlib.sha256()
    for row in sorted(rows, key=lambda row: row.path_bytes):
        sha.update(row.path_bytes)
        sha.update(b"\x00")
        sha.update(U64.pack(row.size))
        sha.update(row.sha256)
    return sha.digest()


@dataclass(slots=True)
class FileRow:
    """One file-table entry: package-relative path, size, whole-file hash."""

    path: str
    size: int
    sha256: bytes

    @property
    def path_bytes(self) -> bytes:
        return self.path.encode("utf-8")

    def encode(self) -> bytes:
        return self.path_bytes + b"\x00" + U64.pack(self.size) + self.sha256


def parse_file_rows(data: memoryview, count: int, offset: int) -> list[FileRow]:
    rows = []
    pos = offset
    blob = bytes(data)
    for _ in range(count):
        end = blob.find(b"\x00", pos)
        if end < 0:
            raise NupError("file table path is not NUL-terminated")
        path = blob[pos:end].decode("utf-8")
        pos = end + 1
        if pos + 8 + DIGEST_SIZE > len(blob):
            raise NupError("file table row overruns the record")
        size, = U64.unpack_from(blob, pos)
        sha256 = blob[pos + 8 : pos + 8 + DIGEST_SIZE]
        pos += 8 + DIGEST_SIZE
        rows.append(FileRow(path, size, sha256))
    return rows


def encode_tlv(tlv_type: int, value: bytes) -> bytes:
    if not 0 <= tlv_type <= TLV_MAX_LENGTH:
        raise NupError(f"TLV type {tlv_type:#x} exceeds u16")
    if len(value) > TLV_MAX_LENGTH:
        raise NupError(
            f"TLV {tlv_type:#x} payload of {len(value)} bytes exceeds the "
            f"u16 length cap {TLV_MAX_LENGTH} (SPEC §10.3)"
        )
    return struct.pack("<HH", tlv_type, len(value)) + value


def parse_tlvs(data: memoryview) -> dict[int, bytes]:
    tlvs: dict[int, bytes] = {}
    pos = 0
    while pos < len(data):
        if pos + 4 > len(data):
            raise NupError("TLV header overruns the TLV block")
        tlv_type, length = struct.unpack_from("<HH", data, pos)
        pos += 4
        if pos + length > len(data):
            raise NupError(f"TLV {tlv_type:#x} value overruns the TLV block")
        tlvs[tlv_type] = bytes(data[pos : pos + length])
        pos += length
    return tlvs


def encode_localized(records: dict[str, bytes]) -> bytes:
    out = bytearray()
    for lang in sorted(records):
        lang_bytes = lang.encode("ascii")
        value = records[lang]
        out.append(len(lang_bytes))
        out += lang_bytes
        out += struct.pack("<H", len(value))
        out += value
    return bytes(out)


def parse_localized(data: memoryview) -> dict[str, bytes]:
    records: dict[str, bytes] = {}
    pos = 0
    while pos < len(data):
        if pos + 1 > len(data):
            raise NupError("localized record overruns the TLV")
        lang_len = data[pos]
        pos += 1
        if pos + lang_len + 2 > len(data):
            raise NupError("localized record overruns the TLV")
        lang = bytes(data[pos : pos + lang_len]).decode("ascii").lower()
        pos += lang_len
        value_len, = struct.unpack_from("<H", data, pos)
        pos += 2
        if pos + value_len > len(data):
            raise NupError("localized record value overruns the TLV")
        records[lang] = bytes(data[pos : pos + value_len])
        pos += value_len
    return records


def scope_prefix(kind: Kind, version: int = 0, index: int = 0) -> str:
    template = KIND_SCOPE_PREFIX[kind]
    return template.format(version=version, index=index)


def align_up(value: int, boundary: int = ALIGN) -> int:
    return (value + boundary - 1) & ~(boundary - 1)
