"""Content-hash recomputation for edited containers.

An edit changes entry bytes, TLVs, or the file table, so every affected
identity must be recomputed: per-package content hashes, scope numbering,
and (for update packages) the materialized-state identity, which needs the
base table and the @deleted manifest (see SPEC_ISSUES
['update-content-hash']).
"""

from .layout import DELETED_NAME, FileRow, Kind, content_hash
from .model import PackageRecord
from .reader import NupReader
from .tree import parse_deleted_manifest


def recompute_identities(
    reader: NupReader,
    records: list[PackageRecord],
    base_path: str | None,
    report,
) -> None:
    base_rows = load_base_rows(base_path)
    for record in records:
        recompute_record_identity(reader, record, base_rows, report)


def load_base_rows(base_path: str | None) -> dict[str, FileRow] | None:
    if base_path is None:
        return None
    from .pack import base_rows_of, load_base_for_diff

    _reader, base_record = load_base_for_diff(base_path)
    return base_rows_of(base_record)


def recompute_record_identity(
    reader: NupReader,
    record: PackageRecord,
    base_rows: dict[str, FileRow] | None,
    report,
) -> None:
    if record.kind is Kind.UPDATE:
        record.content_hash = sorted_identity(update_identity_rows(reader, record, base_rows, report))
    else:
        record.content_hash = sorted_identity(record.files)


def update_identity_rows(
    reader: NupReader,
    record: PackageRecord,
    base_rows: dict[str, FileRow] | None,
    report,
) -> list[FileRow]:
    if base_rows is None:
        report.warnings.append(
            "update-package identity recomputed over its own rows; pass --base "
            "to recompute the materialized-state identity"
        )
        return list(record.files)
    materialized = dict(base_rows)
    for row in record.files:
        if row.path != DELETED_NAME:
            materialized[row.path] = row
    for path in deleted_paths(reader, record):
        materialized.pop(path, None)
    return list(materialized.values())


def deleted_paths(reader: NupReader, record: PackageRecord) -> list[str]:
    for offset, row in enumerate(record.files):
        if row.path == DELETED_NAME:
            entry = reader.entries[record.first_entry_index + offset]
            return parse_deleted_manifest(reader.read_entry_bytes(entry))
    return []


def sorted_identity(rows) -> bytes:
    return content_hash(sorted(rows, key=lambda row: row.path_bytes))


def renumber(records: list[PackageRecord]) -> None:
    first_index = 1
    for record in records:
        record.first_entry_index = first_index
        first_index += len(record.files)
