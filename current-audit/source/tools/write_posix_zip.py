"""Write a deterministic ZIP whose entries advertise Unix file modes."""
from __future__ import annotations

import argparse
import json
import stat
import zipfile
from pathlib import Path


def _mode_map(path: Path) -> dict[str, int]:
    values = json.loads(path.read_text(encoding="utf-8-sig"))
    return {str(item["path"]): int(item["posixMode"]) for item in values}


def write_zip(stage: Path, output: Path, modes_path: Path) -> None:
    modes = _mode_map(modes_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        paths = sorted(stage.rglob("*"), key=lambda item: item.relative_to(stage).as_posix())
        for path in paths:
            name = path.relative_to(stage).as_posix()
            if path.is_dir():
                continue
            if not path.is_file():
                continue
            mode = modes.get(name, 0o644)
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | (mode & 0o7777)) << 16
            with path.open("rb") as handle:
                archive.writestr(info, handle.read(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--modes", type=Path, required=True)
    args = parser.parse_args()
    write_zip(args.stage, args.output, args.modes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
