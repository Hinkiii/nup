"""Tests against the real game dumps (Mario Kart World, Donkey Kong Bananza).

The default suite runs a fast subset (~200 MB of DKB).  Full-scale packs of
the multi-gigabyte dumps are marked ``real``: run them explicitly with
``pytest -m real``.  They write their containers to ``<Jeux>/split/v2/`` and
also settle SPEC §8's arithmetic with real counts.
"""

import hashlib
import shutil

import pytest
from pathlib import Path

from conftest import REAL_DUMPS, tree_of
from nup.reader import read_container

DKB_BASE = REAL_DUMPS / "DKB-base"
DKB_UPDATE = REAL_DUMPS / "DKB-update"
MKW_UPDATES = REAL_DUMPS / "mkw" / "updates" / "917504"
V2_OUT = REAL_DUMPS / "split" / "v2"

requires_dkb = pytest.mark.skipif(
    not DKB_BASE.is_dir() or not DKB_UPDATE.is_dir(), reason="DKB dumps not present"
)


def tree_fingerprint(root: Path) -> dict[str, tuple[int, bytes]]:
    """Streaming (size, sha256) per file so multi-GB trees stay comparable."""
    out = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(chunk)
            out[path.relative_to(root).as_posix()] = (path.stat().st_size, digest.digest())
    return out


def copy_subset(source: Path, target: Path, max_files: int, min_bytes: int) -> Path:
    """A real-content subset: all of exefs plus romfs files up to the caps."""
    target.mkdir(parents=True, exist_ok=True)
    copied = 0
    total = 0
    for group in ("exefs", "romfs"):
        src_group = source / group
        if not src_group.is_dir():
            continue
        dst_group = target / group
        dst_group.mkdir()
        for path in sorted(src_group.rglob("*")):
            if path.is_file():
                rel = path.relative_to(src_group)
                dst = dst_group / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, dst)
                copied += 1
                total += path.stat().st_size
            if group == "romfs" and copied >= max_files and total >= min_bytes:
                break
    return target


@requires_dkb
def test_dkb_subset_pack_verify_extract_roundtrip(tmp_path):
    subset_base = copy_subset(DKB_BASE, tmp_path / "base", 400, 100 << 20)
    subset_update = copy_subset(DKB_UPDATE, tmp_path / "update", 400, 100 << 20)
    from nup.cli import main as nup_main

    base_nup = tmp_path / "DonkeyKongBananza.nup"
    assert nup_main(["pack", str(subset_base), "-o", str(base_nup), "--name=Donkey Kong Bananza",
                     "--display-version=1.0.0"]) == 0
    assert nup_main(["verify", str(base_nup), "--level=full"]) == 0

    update_nup = tmp_path / "DonkeyKongBananza.update.458752.nup"
    assert nup_main(["pack", str(subset_update), "--base", str(base_nup), "-o", str(update_nup),
                     "--version=458752", "--display-version=3.2.0"]) == 0
    assert nup_main(["verify", str(update_nup), "--level=full"]) == 0

    with read_container(str(update_nup)) as reader:
        record = reader.meta.packages[0]
        diff_rows = {row.path for row in record.files}
    assert "exefs/main" in diff_rows, "DKB update ships a new main binary"

    out = tmp_path / "tree"
    assert nup_main(["extract", str(update_nup), "--base", str(base_nup), "--apply", "-o", str(out)]) == 0
    materialized = tree_of(out)
    subset_update_files = tree_of(subset_update)
    for relative, content in subset_update_files.items():
        assert materialized[relative] == content


@requires_dkb
def test_dkb_update_dump_alone_packs_as_base(tmp_path):
    """SPEC §5.2 via the mkw layout: updates/<version> with no base/."""
    from nup.cli import main as nup_main

    subset = copy_subset(MKW_UPDATES, tmp_path / "mkw", 120, 50 << 20)
    out = tmp_path / "mkw.standalone.update.917504.nup"
    assert nup_main(["pack", str(subset), "-o", str(out), "--version=917504",
                     "--display-version=1.8.0"]) == 0
    assert nup_main(["verify", str(out), "--level=full"]) == 0
    with read_container(str(out)) as reader:
        record = reader.meta.packages[0]
    from nup.layout import Kind

    assert record.kind is Kind.BASE
    assert record.version == 917504


def full_pack_base() -> Path:
    from nup.cli import main as nup_main

    V2_OUT.mkdir(parents=True, exist_ok=True)
    out = V2_OUT / "DonkeyKongBananza.nup"
    if not out.exists():
        assert nup_main(["pack", str(DKB_BASE), "-o", str(out), "--name=Donkey Kong Bananza",
                         "--display-version=1.0.0"]) == 0
    assert nup_main(["verify", str(out), "--level=full"]) == 0
    return out


@requires_dkb
@pytest.mark.real
def test_dkb_full_pack_base(tmp_path):
    from nup.cli import main as nup_main

    out = full_pack_base()
    with read_container(str(out)) as reader:
        record = reader.meta.packages[0]
    print(f"DKB base: {len(record.files)} files, container {out.stat().st_size:,} bytes")
    tree = tmp_path / "tree"
    assert nup_main(["extract", str(out), "-o", str(tree)]) == 0
    assert tree_fingerprint(tree / "base") == tree_fingerprint(DKB_BASE)
    shutil.rmtree(tree)


@requires_dkb
@pytest.mark.real
def test_dkb_full_update_diff_and_standalone(tmp_path):
    """SPEC §8's worked example with real numbers."""
    from nup.cli import main as nup_main
    from nup.pack import pack_standalone_container

    base_nup = full_pack_base()
    update_nup = V2_OUT / "DonkeyKongBananza.update.458752.nup"
    assert nup_main(["pack", str(DKB_UPDATE), "--base", str(base_nup), "-o", str(update_nup),
                     "--version=458752", "--display-version=3.2.0"]) == 0
    assert nup_main(["verify", str(update_nup), "--level=full"]) == 0
    with read_container(str(update_nup)) as reader:
        record = reader.meta.packages[0]
        manifest_offset = next(
            index for index, row in enumerate(record.files) if row.path == "@deleted"
        )
        manifest_entry = reader.entries[record.first_entry_index + manifest_offset]
        removed_paths = [
            line for line in reader.read_entry_bytes(manifest_entry).split(b"\n") if line
        ]
        print(
            f"DKB update: {len(record.files)} scope entries "
            f"({len(record.files) - 1} diff rows incl @deleted, {len(removed_paths)} removed paths)"
        )

    standalone = V2_OUT / "DonkeyKongBananza.standalone.update.458752.nup"
    base_record, update_record = pack_standalone_container(
        str(standalone), str(DKB_BASE), str(DKB_UPDATE), update_version=458752,
        base_title_id=0x010074A01BF12000,
    )
    assert nup_main(["verify", str(standalone), "--level=full"]) == 0
    total_entries = sum(len(r.files) for r in (base_record, update_record)) + 1
    print(
        f"standalone: {total_entries} entries (base {len(base_record.files)} + "
        f"update scope {len(update_record.files)} + meta)"
    )

    tree = tmp_path / "tree"
    assert nup_main(["extract", str(update_nup), "--base", str(base_nup), "--apply", "-o", str(tree)]) == 0
    assert tree_fingerprint(tree) == tree_fingerprint(DKB_UPDATE)
    shutil.rmtree(tree)


@requires_dkb
@pytest.mark.real
def test_mkw_full_update_dump_packs_as_base(tmp_path):
    """SPEC §5.2 at full scale: the MKW update dump stored as a base."""
    from nup.cli import main as nup_main

    V2_OUT.mkdir(parents=True, exist_ok=True)
    out = V2_OUT / "MarioKartWorld.standalone.update.917504.nup"
    assert nup_main(["pack", str(MKW_UPDATES), "-o", str(out), "--version=917504",
                     "--display-version=1.8.0"]) == 0
    assert nup_main(["verify", str(out), "--level=full"]) == 0
    with read_container(str(out)) as reader:
        record = reader.meta.packages[0]
    print(f"MKW as-base: {len(record.files)} files, container {out.stat().st_size:,} bytes")
