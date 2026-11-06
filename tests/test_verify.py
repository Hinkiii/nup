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
