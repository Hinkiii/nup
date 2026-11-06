"""``nup pack`` command: dump discovery routing, naming, and TLV arguments."""

import argparse
from pathlib import Path

from .discover import discover_dumps
from .errors import NupError
from .identity import require_title_id
from .layout import TlvType
from .pack import (
    pack_addon_container,
    pack_base_container,
    pack_standalone_container,
    pack_update_container,
)


def command_pack(args) -> int:
    discovery = discover_dumps(args.source)
    tlvs = collect_tlvs(args)
    title_id = parse_title_id(args.title_id)
    application_id = parse_title_id(getattr(args, "application_id", None))
    if args.base is not None:
        return pack_update_flow(args, discovery, tlvs, title_id)
    if args.kind == "standalone":
        return pack_standalone_flow(args, discovery, tlvs, title_id)
    if discovery.mode == "content":
        return pack_single_flow(args, discovery, tlvs, title_id)
    return pack_bundle_flow(args, discovery, tlvs, title_id, args.kind, application_id)


def pack_update_flow(args, discovery, tlvs, title_id) -> int:
    update_dir, version = require_update_dir(discovery, args)
    out = args.out or default_name(update_dir, "update", version)
    record = pack_update_container(
        out,
        update_dir,
        args.base,
        version=version,
        title_id=title_id,
        tlvs=tlvs,
        chain=args.chain,
    )
    print(f"packed {out}: update v{version}, {len(record.files)} diff files")
    return 0


def pack_standalone_flow(args, discovery, tlvs, title_id) -> int:
    update_version = args.version or (max(discovery.updates) if discovery.updates else None)
    if discovery.base_dir is None or update_version is None:
        raise NupError(
            "standalone packing needs a bundle with base/ and updates/<version>/, "
            "plus --version when the dump lacks an updates/ dir"
        )
    update_dir = discovery.updates[update_version]
    out = args.out or default_name(update_dir, "standalone", update_version)
    base_record, update_record = pack_standalone_container(
        out,
        discovery.base_dir,
        update_dir,
        update_version=update_version,
        base_title_id=resolve_title_id(title_id, discovery.base_dir),
        base_tlvs=tlvs,
        update_tlvs=update_tlvs_display(args),
    )
    print(
        f"packed {out}: base ({len(base_record.files)} files) + update v{update_version} "
        f"({len(update_record.files)} diff files)"
    )
    return 0


def pack_single_flow(args, discovery, tlvs, title_id) -> int:
    content_dir = discovery.base_dir
    version = args.version or next(iter(discovery.updates), 0)
    out = args.out or default_name(content_dir, "base", 0)
    record = pack_base_container(
        out,
        content_dir,
        title_id=resolve_title_id(title_id, content_dir),
        version=version,
        tlvs=tlvs,
    )
    print(f"packed {out}: base, {len(record.files)} files")
    return 0


def pack_bundle_flow(args, discovery, tlvs, title_id, kind, application_id=None) -> int:
    if kind == "dlc":
        return pack_dlc_flow(args, discovery, title_id, application_id)
    if discovery.base_dir is None:
        return pack_updates_as_base_flow(args, discovery, tlvs, title_id)
    stem = args.name
    base_out = args.out or default_name(discovery.base_dir, "base", 0, stem)
    title = resolve_title_id(title_id, discovery.base_dir)
    pack_base_container(base_out, discovery.base_dir, title_id=title, tlvs=tlvs)
    written = [base_out]
    written.extend(pack_bundle_updates(args, discovery, title, base_out, stem))
    for line in written:
        print(f"packed {line}")
    return 0


def pack_bundle_updates(args, discovery, application_id, base_out, stem) -> list[str]:
    written = []
    for version in sorted(discovery.updates):
        update_dir = discovery.updates[version]
        update_out = default_name(update_dir, "update", version, stem)
        pack_update_container(
            update_out,
            update_dir,
            base_out,
            version=version,
            application_id=application_id,
            tlvs=update_tlvs_display(args),
        )
        written.append(update_out)
    return written


def pack_updates_as_base_flow(args, discovery, tlvs, title_id) -> int:
    stem = args.name or Path(args.source).resolve().name
    for version in sorted(discovery.updates):
        update_dir = discovery.updates[version]
        out = args.out or default_name(update_dir, "standalone", version, stem)
        record = pack_base_container(
            out,
            update_dir,
            title_id=resolve_title_id(title_id, update_dir),
            version=version,
            tlvs={**tlvs, **(update_tlvs_display(args) or {})},
        )
        print(
            f"packed {out}: update dump alone, stored as base v{version} "
            f"({len(record.files)} files) per SPEC §5.2"
        )
    return 0


def pack_dlc_flow(args, discovery, addon_title_id, application_id) -> int:
    if not discovery.addons:
        raise NupError("this bundle has no dlc/ or addons/ content")
    if application_id is None and discovery.base_dir is not None:
        application_id = derive_application_id(discovery.base_dir)
    if application_id is None:
        raise NupError(
            "--application-id is required: add-on dumps are RomFS-only and "
            "carry no npdm to derive the application id from"
        )
    out = args.out or default_name(discovery.addons[0], "dlc", 0)
    records = pack_addon_container(
        out,
        discovery.addons,
        application_id=application_id,
        title_ids=[addon_title_id] if addon_title_id else None,
    )
    print(f"packed {out}: {len(records)} add-on packages")
    return 0


def derive_application_id(content_dir: str) -> int | None:
    from .identity import exefs_file, read_npdm_program_id

    npdm = exefs_file(content_dir, "main.npdm")
    return read_npdm_program_id(npdm) if npdm else None


def resolve_title_id(title_id, content_dir) -> int:
    return title_id if title_id is not None else require_title_id(content_dir, None)


def require_update_dir(discovery, args) -> tuple[str, int]:
    if discovery.mode == "content":
        if args.version is None:
            raise NupError("--version is required when diffing a bare content directory")
        return discovery.base_dir, args.version
    if not discovery.updates:
        raise NupError("no updates/<version>/ directory found to diff")
    if len(discovery.updates) > 1 and args.version is None:
        raise NupError("--version is required: the bundle carries several updates")
    version = args.version or max(discovery.updates)
    return discovery.updates[version], version


def default_name(source_dir: str, variant: str, version: int, stem: str | None = None) -> str:
    name = stem or Path(source_dir).resolve().name
    suffixes = {
        "base": f"{name}.nup",
        "update": f"{name}.update.{version}.nup",
        "standalone": f"{name}.standalone.update.{version}.nup",
        "dlc": f"{name}.dlc.nup",
    }
    if variant not in suffixes:
        raise NupError(f"unknown naming variant {variant!r}")
    return suffixes[variant]


def parse_title_id(text: str | None) -> int | None:
    return None if text is None else int(text, 16)


def update_tlvs_display(args) -> dict[int, bytes] | None:
    if args.display_version is None:
        return None
    return {TlvType.DISPLAY_VERSION: args.display_version.encode("utf-8")}


def collect_tlvs(args) -> dict[int, bytes]:
    tlvs: dict[int, bytes] = {}
    text_tlvs = {
        TlvType.TITLE_NAME: args.name,
        TlvType.PUBLISHER: args.publisher,
        TlvType.DISPLAY_VERSION: args.display_version,
        TlvType.SOURCE_DUMP: args.provenance,
    }
    for tlv_type, value in text_tlvs.items():
        if value:
            tlvs[tlv_type] = value.encode("utf-8")
    if args.icon:
        tlvs[TlvType.ICON] = Path(args.icon).read_bytes()
    for spec in args.lang_name:
        lang, _, text = spec.partition("=")
        merge_localized(tlvs, TlvType.LOCALIZED_TITLE, lang, text.encode("utf-8"))
    for spec in args.lang_icon:
        lang, _, path = spec.partition("=")
        merge_localized(tlvs, TlvType.LOCALIZED_ICON, lang, Path(path).read_bytes())
    return tlvs


def merge_localized(tlvs: dict[int, bytes], tlv_type: TlvType, lang: str, value: bytes) -> None:
    from .layout import encode_localized, parse_localized

    records = parse_localized(tlvs.get(tlv_type.value, b""))
    records[lang] = value
    tlvs[tlv_type.value] = encode_localized(records)


def add_pack_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("source", help="dump directory (content dir, bundle, or updates/)")
    parser.add_argument("-o", "--out", help="output .nup path (default: convention)")
    parser.add_argument("--kind", choices=("base", "update", "dlc", "standalone"), default=None)
    parser.add_argument("--base", help="base .nup to diff against (update kind)")
    parser.add_argument("--chain", action="append", default=[], metavar="UPDATE_NUP",
                        help="already-packed update(s) the diff lands on, in version order")
    parser.add_argument("--title-id", help="title id, 16 hex digits")
    parser.add_argument("--application-id", help="application id for dlc packs, 16 hex digits")
    parser.add_argument("--version", type=int, help="package version (NCM-style u32)")
    parser.add_argument("--name")
    parser.add_argument("--display-version")
    parser.add_argument("--publisher")
    parser.add_argument("--icon", help="icon file for the default-language TLV")
    parser.add_argument("--lang-name", action="append", default=[], metavar="LANG=TEXT")
    parser.add_argument("--lang-icon", action="append", default=[], metavar="LANG=FILE")
    parser.add_argument("--provenance", help="source dump provenance string (TLV 0x000C)")
