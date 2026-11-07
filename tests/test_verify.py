"""Verification levels and corruption detection across the hash chain."""

import pytest

from conftest import flip_byte
from nup.errors import NupError, VerificationError
from nup.reader import read_container
from nup.verify import verify_container


def test_clean_container_passes_every_level(base_nup):
    with read_container(str(base_nup)) as reader:
        for level in ("bind", "package", "full"):
            report = verify_container(reader, level)
            assert report.level == level


def test_data_corruption_passes_bind_but_fails_package(base_nup):
    """The 0x200 entry hashes and meta file tables catch data corruption."""
    with read_container(str(base_nup)) as reader:
        entry = reader.entry("base/romfs/big.bin")
        offset = reader.data_start + entry.data_offset + 0x300
    corrupt = flip_byte(base_nup, offset)
    with read_container(str(corrupt), check_bind=False) as reader:
        reader.check_bind()
        with pytest.raises(VerificationError):
            verify_container(reader, "package")
    with read_container(str(corrupt)) as reader:
        with pytest.raises(VerificationError):
            verify_container(reader, "full")


def test_lazy_read_detects_corruption(base_nup):
    with read_container(str(base_nup)) as reader:
        entry = reader.entry("base/romfs/small.bin")
        offset = reader.data_start + entry.data_offset
    corrupt = flip_byte(base_nup, offset)
    with read_container(str(corrupt)) as reader:
        with pytest.raises(VerificationError):
            reader.read_file("base/romfs/small.bin")


def test_string_table_corruption_fails_bind_with_nup_error(base_nup):
    with read_container(str(base_nup)) as reader:
        offset = reader.data_start - 0x10
    corrupt = flip_byte(base_nup, offset)
    with pytest.raises(NupError):
        read_container(str(corrupt))


def test_entry_table_corruption_fails_header_hash(base_nup):
    """The meta header hash covers the entry table (SPEC §6.1)."""
    corrupt = flip_byte(base_nup, 0x30)
    with read_container(str(corrupt), check_bind=False) as reader:
        with pytest.raises(VerificationError):
            reader.check_header_hash()


def test_meta_record_corruption_fails_digest(base_nup):
    with read_container(str(base_nup)) as reader:
        offset = reader.data_start + 0x40
    corrupt = flip_byte(base_nup, offset)
    with pytest.raises(NupError):
        read_container(str(corrupt), check_bind=False)


def test_corrupt_bind_open_is_rejected(base_nup):
    with read_container(str(base_nup)) as reader:
        entry = reader.entry("base/romfs/big.bin")
        offset = reader.data_start + entry.data_offset
    corrupt = flip_byte(base_nup, offset)
    with read_container(str(corrupt)) as reader:
        with pytest.raises(VerificationError):
            verify_container(reader, "package")


def test_padding_corruption_is_outside_the_hash_chain(base_nup):
    """Entry padding is not hashed: corruption there stays undetected by design.

    The spec's hash chain covers entry data and tables; alignment padding is
    neither.  Documented so the behavior is a decision, not an accident.
    """
    with read_container(str(base_nup)) as reader:
        entry = reader.entry("base/romfs/data/table.bin")
        padding_start = reader.data_start + entry.data_offset + entry.size
    corrupt = flip_byte(base_nup, padding_start + 1)
    with read_container(str(corrupt)) as reader:
        verify_container(reader, "full")


def test_package_level_targeting(base_nup):
    with read_container(str(base_nup)) as reader:
        report = verify_container(reader, "package", "base")
        assert report.packages_checked == ["base"]
        with pytest.raises(NupError):
            verify_container(reader, "package", "update")
        with pytest.raises(NupError):
            verify_container(reader, "package", "nonexistent")


def test_truncated_data_fails_full_verify(base_nup):
    """Bind checks are O(TOC); truncation surfaces at data level (SPEC §6.3)."""
    data = base_nup.read_bytes()
    truncated = base_nup.with_suffix(".trunc.nup")
    truncated.write_bytes(data[: len(data) - 1])
    with read_container(str(truncated)) as reader:
        with pytest.raises(NupError):
            verify_container(reader, "full")


def test_verify_report_counts(base_nup):
    with read_container(str(base_nup)) as reader:
        report = verify_container(reader, "full")
    with read_container(str(base_nup)) as reader:
        assert report.entries_hashed == len(reader.meta.packages[0].files)
    assert report.bytes_hashed > 0


def test_unknown_feature_flags_are_rejected(base_nup):
    """The 0x3C feature-flags field is zero in v2.0; unknown bits fail closed."""
    with read_container(str(base_nup)) as reader:
        meta_offset = reader.data_start + reader.entries[0].data_offset
    data = bytearray(base_nup.read_bytes())
    data[meta_offset + 0x3C] = 0x01
    corrupt = base_nup.with_suffix(".flags.nup")
    corrupt.write_bytes(data)
    with pytest.raises(NupError):
        read_container(str(corrupt))


def _craft_container(tmp_path, *, entry_count=0, table_size=0, body=b""):
    """A minimal hostile container: header + body, nothing valid inside."""
    import struct

    from nup.layout import HFS0_MAGIC

    path = tmp_path / "hostile.nup"
    path.write_bytes(
        struct.pack("<4sIII", HFS0_MAGIC, entry_count, table_size, 0) + body
    )
    return path


def test_declared_entry_table_larger_than_container_fails_fast(tmp_path):
    """issue #27: a huge declared count must not make the reader allocate
    or loop - it fails on the file-size bound immediately."""
    import time

    from nup.errors import NupError

    started = time.monotonic()
    with pytest.raises(NupError):
        read_container(str(_craft_container(tmp_path, entry_count=1 << 30, table_size=0)))
    assert time.monotonic() - started < 2.0


def test_hostile_string_table_size_fails_clean(tmp_path):
    from nup.errors import NupError

    with pytest.raises(NupError):
        read_container(str(_craft_container(tmp_path, entry_count=1, table_size=0xFFFF_FFFF)))


def test_meta_record_size_sanity_cap(base_nup, tmp_path):
    """issue #27: a hostile meta entry size cannot push a huge read into RAM."""
    from nup.errors import NupError

    data = bytearray(base_nup.read_bytes())
    data[0x10 + 0x08:0x10 + 0x10] = (1 << 62).to_bytes(8, "little")  # entry 0 size
    data[0x10 + 0x20:0x10 + 0x40] = bytes(32)                        # prefix hash field
    hostile = tmp_path / "hostile_meta.nup"
    hostile.write_bytes(data)
    with pytest.raises(NupError):
        read_container(str(hostile))


def test_absolute_and_traversal_file_table_paths_are_rejected(base_nup, tmp_path):
    """issue #24: a re-signed container with hostile paths must fail at
    open, before anything is written to disk."""
    for evil in (b"/tmp/nup-pwned", b"x/../../nup-pwned"):
        data = bytearray(base_nup.read_bytes())
        meta_offset = data_start_of(data)
        needle = b"romfs/small.bin\x00"
        pos = data.find(needle, meta_offset)
        assert pos > 0
        data[pos:pos + len(needle)] = evil.ljust(len(needle), b"\x00")[:len(needle)]
        re_sign_meta(data, meta_offset)  # an attacker re-signs after tampering
        hostile = tmp_path / "evil.nup"
        hostile.write_bytes(data)
        with pytest.raises(NupError):
            read_container(str(hostile))


def data_start_of(data):
    import struct

    _magic, count, table_size, _reserved = struct.unpack_from("<4sIII", data)
    raw = 0x10 + 0x40 * count + table_size
    return raw + (-raw % 0x200)


def re_sign_meta(data, meta_start):
    """Recompute the meta digest the way a malicious packer would."""
    import hashlib
    import struct

    entry0_size = struct.unpack_from("<Q", data, 0x10 + 0x08)[0]
    meta_end = meta_start + entry0_size
    body = data[meta_start:meta_end - 32]
    data[meta_end - 32:meta_end] = hashlib.sha256(bytes(body)).digest()
