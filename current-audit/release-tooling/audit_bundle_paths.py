"""Canonical repository versus extracted-audit-bundle path resolution."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BundleLayout:
    bundle_root: Path
    source_root: Path
    installer_source_root: Path
    release_tooling_root: Path
    release_e2e_root: Path


def resolve_bundle_layout(anchor: Path) -> BundleLayout:
    anchor = anchor.resolve()
    for candidate in (anchor, *anchor.parents):
        source_root = candidate / "source"
        installer_source_root = candidate / "installer-source"
        release_tooling_root = candidate / "release-tooling"
        if not release_tooling_root.is_dir():
            release_tooling_root = candidate / "tools"
        release_e2e_root = candidate / "automation" / "release-e2e"
        if source_root.is_dir() and installer_source_root.is_dir() and release_tooling_root.is_dir() and release_e2e_root.is_dir():
            return BundleLayout(candidate, source_root, installer_source_root, release_tooling_root, release_e2e_root)
    raise AssertionError(f"Could not identify a repository or canonical audit bundle root from {anchor}")
