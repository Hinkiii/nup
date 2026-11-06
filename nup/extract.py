"""Extraction and materialization: container scopes -> game-ready trees.

Materialization overlays update diffs onto the base in ascending version
order, checking each diff's base content hash against the materialized
identity it lands on (SPEC §5.1), then consumes every @deleted manifest.
"""

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path

from .errors import NupError
from .layout import (
    DELETED_NAME,
    FileRow,
    Kind,
    content_hash,
    scope_prefix,
)
from .model import addon_index
from .reader import NupReader
from .tree import parse_deleted_manifest


@dataclass(slots=True)
class ExtractReport:
    files_written: int = 0
    bytes_written: int = 0
    deleted_paths: list[str] = field(default_factory=list)
    applied_versions: list[int] = field(default_factory=list)
    roots: list[str] = field(default_factory=list)

    def merge(self, other: "ExtractReport") -> None:
        self.files_written += other.files_written
        self.bytes_written += other.bytes_written
        self.deleted_paths.extend(other.deleted_paths)
        self.applied_versions.extend(other.applied_versions)
        self.roots.extend(other.roots)


Locator = tuple[NupReader, int]
State = dict[str, tuple[FileRow, Locator]]


def scope_of(record) -> str:
    return scope_prefix(record.kind, record.version, addon_index(record))


def extract_package(
    reader: NupReader,
    record,
    out_dir: str,
    *,
    flatten: bool = False,
    verify: bool = True,
) -> ExtractReport:
    target_root = out_dir if flatten else os.path.join(out_dir, scope_of(record))
    report = ExtractReport(roots=[target_root])
    for offset, row in enumerate(record.files):
        entry = reader.entries[record.first_entry_index + offset]
        target = Path(target_root, *row.path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        copy_verified(reader, entry, row, target, verify)
        report.files_written += 1
        report.bytes_written += row.size
    return report


def extract_container(reader: NupReader, out_dir: str, *, verify: bool = True) -> ExtractReport:
    report = ExtractReport()
    for record in reader.meta.packages:
        report.merge(extract_package(reader, record, out_dir, verify=verify))
    return report


def copy_verified(reader: NupReader, entry, row: FileRow, target: Path, verify: bool) -> None:
    digest = hashlib.sha256()
    with open(target, "wb") as out:
        for chunk in reader.iter_entry_chunks(entry):
            if verify:
                digest.update(chunk)
            out.write(chunk)
    if verify and digest.digest() != row.sha256:
        raise NupError(f"entry {entry.name!r} failed its file-table hash on extract")


def materialize(
    reader: NupReader,
    out_dir: str,
    *,
    base_reader: NupReader | None = None,
    chain: "list[NupReader] | None" = None,
    verify: bool = True,
) -> ExtractReport:
    """Game-ready tree: base overlaid with update diffs in version order.

    ``chain`` lists intermediate update containers (ascending version) to
    apply before ``reader``'s own updates, so chained diffs can land (SPEC
    §5.1).  Each diff's base content hash must equal the materialized
    identity it lands on; @deleted manifests are consumed, not written.
    """
    updates = sorted(
        (record for record in reader.meta.packages if record.kind is Kind.UPDATE),
        key=lambda record: record.version,
    )
    addons = [record for record in reader.meta.packages if record.kind is Kind.ADDON]
    bases = [record for record in reader.meta.packages if record.kind is Kind.BASE]
    report = ExtractReport()
    state: State = {}
    if bases:
        if base_reader is not None:
            raise NupError("--base is unnecessary: this container already carries the base")
        state = initial_state(reader, bases[0])
    elif updates or chain:
        state = bind_base_tree(bases, updates, base_reader)
    elif not addons:
        raise NupError("container has no base, update, or add-on packages to materialize")
    for link in chain or []:
        apply_updates(link, updates_of(link), state, report)
    apply_updates(reader, updates, state, report)
    if state:
        write_state(state, out_dir, verify, report)
        report.roots.append(out_dir)
    for record in addons:
        report.merge(extract_package(reader, record, out_dir, verify=verify))
    return report


def updates_of(reader: NupReader):
    return sorted(
        (record for record in reader.meta.packages if record.kind is Kind.UPDATE),
        key=lambda record: record.version,
    )


def initial_state(reader: NupReader, record) -> State:
    return {
        row.path: (row, (reader, record.first_entry_index + offset))
        for offset, row in enumerate(record.files)
    }


def bind_base_tree(bases, updates, base_reader: NupReader | None) -> State:
    if base_reader is None:
        raise NupError(
            "materializing an update container requires --base <base.nup>"
        )
    base_record = require_single(base_reader, Kind.BASE, "base")
    return initial_state(base_reader, base_record)


def require_single(reader: NupReader, kind: Kind, label: str):
    found = [record for record in reader.meta.packages if record.kind is kind]
    if len(found) != 1:
        raise NupError(f"expected exactly one {label} package, found {len(found)}")
    return found[0]


def apply_updates(reader: NupReader, updates, state: State, report: ExtractReport) -> None:
    for record in updates:
        if record.base_content_hash != identity_of(state):
            raise NupError(
                f"update v{record.version} binds to base content hash "
                f"{record.base_content_hash.hex()} but the materialized tree is "
                f"{identity_of(state).hex()}"
            )
        for offset, row in enumerate(record.files):
            if row.path == DELETED_NAME:
                entry = reader.entries[record.first_entry_index + offset]
                removed = parse_deleted_manifest(reader.read_entry_bytes(entry))
                for path in removed:
                    if state.pop(path, None) is None:
                        raise NupError(
                            f"the v{record.version} @deleted manifest names {path!r}, "
                            "which the tree does not contain"
                        )
                report.deleted_paths.extend(removed)
                continue
            state[row.path] = (row, (reader, record.first_entry_index + offset))
        report.applied_versions.append(record.version)


def identity_of(state: State) -> int:
    rows = [state[path][0] for path in sorted(state)]
    return content_hash(rows)


def write_state(state: State, out_dir: str, verify: bool, report: ExtractReport) -> None:
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    for path, (row, (reader, index)) in sorted(state.items()):
        entry = reader.entries[index]
        target = Path(out_dir, *path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        copy_verified(reader, entry, row, target, verify)
        report.files_written += 1
        report.bytes_written += row.size


def extract_with_options(
    reader: NupReader,
    out_dir: str,
    *,
    package: str | None = None,
    apply: bool = False,
    base_reader: NupReader | None = None,
    chain: "list[NupReader] | None" = None,
    verify: bool = True,
) -> ExtractReport:
    from .verify import select_packages

    if package is not None:
        report = ExtractReport()
        for record in select_packages(reader, package):
            report.merge(extract_package(reader, record, out_dir, verify=verify))
        return report
    if apply:
        return materialize(reader, out_dir, base_reader=base_reader, chain=chain, verify=verify)
    return extract_container(reader, out_dir, verify=verify)


def summarize(report: ExtractReport) -> str:
    summary = f"extracted {report.files_written} files, {report.bytes_written:,} bytes"
    if report.applied_versions:
        summary += f"; applied updates {report.applied_versions}"
    if report.deleted_paths:
        summary += f"; deleted {len(report.deleted_paths)} paths"
    return summary
