from __future__ import annotations

from dataclasses import dataclass
import importlib.util
import sys
from pathlib import Path


@dataclass(frozen=True)
class BundleLayout:
    """Explicit repository/canonical-bundle roots used by path-sensitive tests."""

    bundle_root: Path
    source_root: Path
    installer_source_root: Path
    release_tooling_root: Path
    release_e2e_root: Path


def resolve_bundle_layout(anchor: Path) -> BundleLayout:
    anchor = anchor.resolve()
    for candidate in (anchor, *anchor.parents):
        for helper in (candidate / "release-tooling/audit_bundle_paths.py", candidate / "tools/audit_bundle_paths.py"):
            if not helper.is_file():
                continue
            spec = importlib.util.spec_from_file_location("devfleet_audit_bundle_paths", helper)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            # Dataclasses and other introspection-based modules expect the
            # executing module to be registered, as it is during ordinary
            # imports.  Preserve that invariant for relocated bundles.
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            layout = module.resolve_bundle_layout(anchor)
            return BundleLayout(layout.bundle_root, layout.source_root, layout.installer_source_root, layout.release_tooling_root, layout.release_e2e_root)
    raise AssertionError(f"Could not identify a repository or canonical audit bundle root from {anchor}")
