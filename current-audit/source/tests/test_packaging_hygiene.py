from pathlib import Path
import re


ROOT = Path(__file__).parents[1]


def test_current_operational_docs_do_not_use_stale_release_examples():
    current_docs = [
        ROOT / "README-FIRST.md",
        ROOT.parent / "installer-source/BUILD-INSTRUCTIONS.md",
        ROOT.parent / "installer-source/BUILDING.md",
        ROOT.parent / "installer-source/CLEAN-ROOM-INSTALL.md",
        ROOT.parent / "installer-source/RELEASING.md",
    ]
    stale = (r"(?<![0-9])v?1\.2\.1(?![0-9])", r"(?<![0-9])v?1\.2\.9(?![0-9])", r"(?<![0-9])v?1\.2\.12(?![0-9])")
    for path in current_docs:
        text = path.read_text(encoding="utf-8").lower()
        assert not any(re.search(value, text) for value in stale), path


def test_installer_source_packaging_excludes_pytest_cache():
    builder = (ROOT / "tools/Build-InstallerSourceZip.ps1").read_text(encoding="utf-8")
    assert "\\.pytest_cache" in builder
