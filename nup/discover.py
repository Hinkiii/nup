"""Dump discovery: recognize the on-disc layouts the packer accepts.

Accepted layouts: a content directory (exefs/ and/or romfs/), a bundle
(base/ plus updates/<decimal>/ plus optional dlc/ or addons/), or an
update-only bundle (updates/ without base/), which packs as a base
(SPEC §5.2).
"""

from dataclasses import dataclass, field
import os
import re

from .errors import NupError

DECIMAL = re.compile(r"^\d+$")
CONTENT_MARKERS = ("exefs", "romfs")


@dataclass(slots=True)
class Discovery:
    mode: str
    base_dir: str | None = None
    updates: dict[int, str] = field(default_factory=dict)
    addons: list[str] = field(default_factory=list)


def discover_dumps(source: str) -> Discovery:
    if is_content_dir(source):
        return Discovery(mode="content", base_dir=source)
    if os.path.isdir(os.path.join(source, "base")) or os.path.isdir(os.path.join(source, "updates")):
        return discover_bundle(source)
    raise NupError(
        f"{source!r} is neither a content directory (exefs/ or romfs/) nor a dump "
        "bundle (base/, updates/, dlc/)"
    )


def discover_bundle(source: str) -> Discovery:
    base = os.path.join(source, "base")
    base_dir = base if os.path.isdir(base) and bundle_has_files(base) else None
    updates = collect_updates(os.path.join(source, "updates"))
    addons = collect_addons(source)
    mode = "bundle" if base_dir else "updates-only"
    if base_dir is None and not updates and not addons:
        raise NupError(f"{source!r} has no packable content")
    return Discovery(mode=mode, base_dir=base_dir, updates=updates, addons=addons)


def is_content_dir(path: str) -> bool:
    return any(os.path.isdir(os.path.join(path, marker)) for marker in CONTENT_MARKERS)


def bundle_has_files(path: str) -> bool:
    for _dirpath, _dirnames, filenames in os.walk(path):
        for filename in filenames:
            if not filename.endswith(".listing"):
                return True
    return False


def collect_updates(updates_dir: str) -> dict[int, str]:
    updates: dict[int, str] = {}
    if not os.path.isdir(updates_dir):
        return updates
    for name in sorted(os.listdir(updates_dir)):
        path = os.path.join(updates_dir, name)
        if DECIMAL.match(name) and os.path.isdir(path) and bundle_has_files(path):
            updates[int(name)] = path
    return updates


def collect_addons(source: str) -> list[str]:
    addons = []
    for parent in ("dlc", "addons"):
        addon_root = os.path.join(source, parent)
        if not os.path.isdir(addon_root):
            continue
        for name in sorted(os.listdir(addon_root)):
            path = os.path.join(addon_root, name)
            if is_content_dir(path):
                addons.append(path)
                continue
            for nested in sorted(os.listdir(path)) if os.path.isdir(path) else ():
                nested_path = os.path.join(path, nested)
                if is_content_dir(nested_path):
                    addons.append(nested_path)
    return addons
