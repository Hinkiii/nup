"""NUP v2 packer orchestration: dump trees and base containers -> .nup files.

Container variants (SPEC §1 rule 7, §5): base, diff update against a base
package, standalone (base + one diff update), and add-on collections.
Packing a lone update dump emits a base container instead (SPEC §5.2).

Blob and the tree-to-record machinery live in writer and diff; this module
routes user intent (base, update, standalone, dlc) into them.
"""

from dataclasses import dataclass, field
import os

from .diff import base_rows_of, chain_state, pack_tree_package
from .errors import NupError
from .layout import Kind
from .model import PackageRecord
from .reader import NupReader, read_container
from .writer import Blob, write_container


@dataclass(slots=True)
class PackageInput:
    kind: Kind
    content_dir: str
    version: int = 0
    addon_position: int = 0
    title_id: int | None = None
    application_id: int = 0
    tlvs: dict[int, bytes] = field(default_factory=dict)


@dataclass(slots=True)
class PackedPackage:
    record: PackageRecord
    blobs: list[Blob]


def pack_base_container(
    out_path: str,
    content_dir: str,
    *,
    title_id: int,
    version: int = 0,
    tlvs: dict[int, bytes] | None = None,
) -> PackageRecord:
    package_input = PackageInput(
        Kind.BASE, content_dir, version=version, title_id=title_id, tlvs=tlvs or {}
    )
    packed = pack_tree_package(package_input, first_entry_index=1)
    write_container(out_path, [packed])
    return packed.record


def load_base_for_diff(base_path: str) -> tuple[NupReader, PackageRecord]:
    reader = read_container(base_path)
    bases = [record for record in reader.meta.packages if record.kind is Kind.BASE]
    if not bases:
        reader.close()
        raise NupError(f"{base_path!r} carries no base package to diff against")
    return reader, bases[0]


def pack_update_container(
    out_path: str,
    content_dir: str,
    base_path: str,
    *,
    version: int,
    title_id: int | None = None,
    application_id: int | None = None,
    tlvs: dict[int, bytes] | None = None,
    chain: list[str] | None = None,
) -> PackageRecord:
    """Diff container against a base, optionally landing on already-packed
    updates whose materialized state is the diff target (SPEC §5.1 chains)."""
    _reader, base_record = load_base_for_diff(base_path)
    application = application_id if application_id is not None else base_record.title_id
    target_rows, target_identity = chain_state(base_record, chain or [])
    package_input = PackageInput(
        Kind.UPDATE,
        content_dir,
        version=version,
        title_id=title_id if title_id is not None else application + 0x800,
        application_id=application,
        tlvs=tlvs or {},
    )
    packed = pack_tree_package(
        package_input,
        first_entry_index=1,
        base_rows=target_rows,
        base_identity=target_identity,
    )
    write_container(out_path, [packed])
    return packed.record


def pack_standalone_container(
    out_path: str,
    base: str,
    update_dir: str,
    *,
    update_version: int,
    base_title_id: int | None = None,
    base_version: int = 0,
    base_tlvs: dict[int, bytes] | None = None,
    update_tlvs: dict[int, bytes] | None = None,
    update_title_id: int | None = None,
) -> tuple[PackageRecord, PackageRecord]:
    """Base and its diff in one container so the pair travels together (§5.3)."""
    base_record, base_blobs = load_or_pack_base(base, base_title_id, base_version, base_tlvs)
    application = base_record.title_id
    update_input = PackageInput(
        Kind.UPDATE,
        update_dir,
        version=update_version,
        title_id=update_title_id if update_title_id is not None else application + 0x800,
        application_id=application,
        tlvs=update_tlvs or {},
    )
    packed_update = pack_tree_package(
        update_input,
        first_entry_index=1 + len(base_record.files),
        base_rows=base_rows_of(base_record),
    )
    write_container(
        out_path,
        [PackedPackage(base_record, base_blobs), packed_update],
    )
    return base_record, packed_update.record


def load_or_pack_base(base: str, title_id, version: int, tlvs) -> tuple[PackageRecord, list[Blob]]:
    if base.endswith(".nup") and os.path.isfile(base):
        _reader, base_record = load_base_for_diff(base)
        return base_record, reuse_container_blobs_from(base, base_record)
    if title_id is None:
        raise NupError("standalone packing from a dump dir needs --title-id")
    packed = pack_tree_package(
        PackageInput(Kind.BASE, base, version=version, title_id=title_id, tlvs=tlvs or {}),
        first_entry_index=1,
    )
    return packed.record, packed.blobs


def reuse_container_blobs(reader: NupReader, record: PackageRecord) -> list[Blob]:
    return reuse_container_blobs_from(reader.path, record)


def reuse_container_blobs_from(container_path: str, record: PackageRecord) -> list[Blob]:
    """Point blobs at the existing container's bytes so standalone packing
    streams the base instead of re-reading the dump."""
    with read_container(container_path) as reader:
        return [blob_for_entry(reader, record, offset) for offset in range(len(record.files))]


def blob_for_entry(reader: NupReader, record: PackageRecord, offset: int) -> Blob:
    entry = reader.entries[record.first_entry_index + offset]
    return Blob(
        entry.name,
        entry.size,
        entry.prefix_hash,
        fs_path=reader.path,
        offset=reader.data_start + entry.data_offset,
    )


def pack_addon_container(
    out_path: str,
    addon_dirs: list[str],
    *,
    application_id: int,
    title_ids: list[int] | None = None,
    tlvs: list[dict[int, bytes]] | None = None,
) -> list[PackageRecord]:
    if not addon_dirs:
        raise NupError("an add-on container needs at least one add-on dump")
    packed = []
    first_index = 1
    for position, content_dir in enumerate(sorted(addon_dirs)):
        package_input = addon_input(position, content_dir, application_id, title_ids, tlvs)
        packed_package = pack_tree_package(package_input, first_entry_index=first_index)
        packed.append(packed_package)
        first_index += len(packed_package.record.files)
    write_container(out_path, packed)
    return [packed_package.record for packed_package in packed]


def addon_input(position: int, content_dir: str, application_id: int, title_ids, tlvs) -> PackageInput:
    """Scope index follows the console id: title - application - 0x1000
    (DKB's dlc dump is index 1), so writer and reader derive the same
    `addon/N/...` paths.  Without explicit ids the first add-on is index 1,
    matching Nintendo's observed assignment."""
    if title_ids and title_ids[position]:
        title_id = title_ids[position]
        scope_index = title_id - application_id - 0x1000
        if scope_index < 0:
            raise NupError(
                f"add-on title id {title_id:#x} is smaller than application "
                f"{application_id:#x} + 0x1000 (SPEC §4)"
            )
    else:
        title_id = application_id + 0x1000 + position + 1
        scope_index = position + 1
    return PackageInput(
        Kind.ADDON,
        content_dir,
        addon_position=scope_index,
        title_id=title_id,
        application_id=application_id,
        tlvs=(tlvs[position] if tlvs else {}) or {},
    )
