"""Single package-version source shared by API, UI, and release tooling."""
from __future__ import annotations

import os
from pathlib import Path


def package_version() -> str:
    configured = str(os.environ.get("DEVFLEET_VERSION", "")).strip()
    candidates = [Path(configured)] if configured else []
    here = Path(__file__).resolve()
    candidates.extend((here.parents[1] / "VERSION", here.parents[2] / "VERSION"))
    for path in candidates:
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            return value
    raise RuntimeError("DevFleet VERSION file is missing or empty; refusing a stale fallback.")


__version__ = package_version()
