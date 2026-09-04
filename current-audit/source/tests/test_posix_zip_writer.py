import json
import zipfile

from source.tools.write_posix_zip import write_zip


def test_zip_writer_marks_unix_origin_and_preserves_contract_modes(tmp_path):
    stage = tmp_path / "stage"
    (stage / "source" / "bin").mkdir(parents=True)
    (stage / "source" / "bin" / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (stage / "source" / "README.md").write_text("readme\n", encoding="utf-8")
    modes = stage / "SOURCE-MODES.json"
    modes.write_text(
        json.dumps(
            [
                {"path": "source/README.md", "posixMode": 420},
                {"path": "source/bin/run.sh", "posixMode": 493},
            ]
        ),
        encoding="utf-8",
    )
    output = tmp_path / "audit.zip"
    write_zip(stage, output, modes)

    with zipfile.ZipFile(output) as archive:
        entries = {item.filename: item for item in archive.infolist()}
    assert entries["source/README.md"].create_system == 3
    assert entries["source/README.md"].external_attr >> 16 & 0o777 == 0o644
    assert entries["source/bin/run.sh"].create_system == 3
    assert entries["source/bin/run.sh"].external_attr >> 16 & 0o777 == 0o755
    assert "source/" not in entries
