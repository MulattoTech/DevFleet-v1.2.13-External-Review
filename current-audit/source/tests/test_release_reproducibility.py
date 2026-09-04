from __future__ import annotations

import hashlib
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).parents[1]
BUILDER = ROOT / "tools" / "build_release.py"
sys.path.insert(0, str(ROOT / "tools"))
from build_release import files


FIXTURE_FILES = {
    "VERSION": b"1.2.13\n",
    "Zeta.txt": b"upper\n",
    "alpha.txt": b"lower\n",
    "app/Cafe.txt": b"ascii\n",
    "app/caf\u00e9.txt": b"unicode\n",
}


def _source(root: Path, names: list[str]) -> Path:
    root.mkdir()
    for name in names:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(FIXTURE_FILES[name])
    return root


def _build(source: Path, old_portable: Path, output: Path, cwd: Path) -> tuple[Path, Path]:
    output.mkdir()
    subprocess.run(
        [
            sys.executable,
            str(BUILDER),
            "--source",
            str(source),
            "--old-portable",
            str(old_portable),
            "--output-dir",
            str(output),
        ],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return (
        output / "devfleet-v1.2.13.tar.gz",
        output / "DevFleet-v1.2.13-Portable-Codebase-Verified-r1.zip",
    )


def test_files_use_canonical_utf8_posix_order_independent_of_creation_order(tmp_path: Path):
    names = list(FIXTURE_FILES)
    first = _source(tmp_path / "first", names)
    second = _source(tmp_path / "second", list(reversed(names)))
    expected = sorted(names, key=lambda name: name.encode("utf-8"))
    assert [path.relative_to(first).as_posix() for path in files(first)] == expected
    assert [path.relative_to(second).as_posix() for path in files(second)] == expected


def test_two_clean_room_builds_are_byte_identical_with_normalized_metadata(tmp_path: Path):
    names = list(FIXTURE_FILES)
    first = _source(tmp_path / "source-one", names)
    second = _source(tmp_path / "source-two", list(reversed(names)))
    old_portable = tmp_path / "old-portable.zip"
    with zipfile.ZipFile(old_portable, "w") as archive:
        archive.writestr("historical-note.txt", b"preserved\n")

    first_tar, first_zip = _build(first, old_portable, tmp_path / "output-one", tmp_path)
    second_tar, second_zip = _build(second, old_portable, tmp_path / "output-two", tmp_path / "source-two")
    assert first_tar.read_bytes() == second_tar.read_bytes()
    assert first_zip.read_bytes() == second_zip.read_bytes()
    assert hashlib.sha256(first_tar.read_bytes()).digest() == hashlib.sha256(second_tar.read_bytes()).digest()
    assert hashlib.sha256(first_zip.read_bytes()).digest() == hashlib.sha256(second_zip.read_bytes()).digest()

    with tarfile.open(first_tar, "r:gz") as archive:
        for member in archive.getmembers():
            assert member.mtime == 0
            assert member.uid == member.gid == 0
            assert member.mode in {0o644, 0o755}
    with zipfile.ZipFile(first_zip) as archive:
        for member in archive.infolist():
            assert member.date_time == (1980, 1, 1, 0, 0, 0)
            assert member.create_system == 3
            assert stat.S_IMODE(member.external_attr >> 16) in {0o644, 0o755}
