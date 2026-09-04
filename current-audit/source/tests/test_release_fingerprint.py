import json
import os
from pathlib import Path
import shutil

from tools.release_fingerprint import build_fingerprint


def test_shipping_fingerprint_changes_for_shipping_mutation(tmp_path: Path):
    source = tmp_path / "source"
    installer = tmp_path / "installer"
    source.mkdir()
    installer.mkdir()
    (source / "VERSION").write_text("1.2.13\n", encoding="utf-8")
    (source / "payload.sh").write_text("echo one\n", encoding="utf-8")
    (installer / "INSTALLER_VERSION").write_text("1.4.1\n", encoding="utf-8")
    first = build_fingerprint(source, installer)
    (source / "payload.sh").write_text("echo two\n", encoding="utf-8")
    second = build_fingerprint(source, installer)
    assert first["releaseFingerprintId"] != second["releaseFingerprintId"]


def test_nonshipping_harness_is_outside_shipping_fingerprint(tmp_path: Path):
    source = tmp_path / "source"
    installer = tmp_path / "installer"
    automation = tmp_path / "automation"
    source.mkdir()
    installer.mkdir()
    automation.mkdir()
    (source / "VERSION").write_text("1.2.13\n", encoding="utf-8")
    (installer / "INSTALLER_VERSION").write_text("1.4.1\n", encoding="utf-8")
    first = build_fingerprint(source, installer)
    (automation / "harness.ps1").write_text("Write-Output pass\n", encoding="utf-8")
    second = build_fingerprint(source, installer)
    assert first["releaseFingerprintId"] == second["releaseFingerprintId"]
    assert first["toolingFingerprint"]["toolingFingerprintId"] != second["toolingFingerprint"]["toolingFingerprintId"]


def test_fingerprint_json_is_machine_readable(tmp_path: Path):
    source = tmp_path / "source"
    installer = tmp_path / "installer"
    source.mkdir()
    installer.mkdir()
    (source / "VERSION").write_text("1.2.13\n", encoding="utf-8")
    (installer / "INSTALLER_VERSION").write_text("1.4.1\n", encoding="utf-8")
    result = build_fingerprint(source, installer)
    assert result["schemaVersion"] == 2
    assert len(result["releaseFingerprintId"]) == 64
    assert json.loads(json.dumps(result))["devfleetVersion"] == "1.2.13"


def _tree(root: Path) -> tuple[Path, Path, Path]:
    source = root / "source"
    installer = root / "installer"
    outputs = root / "outputs"
    (source / "templates/demo/.devfleet").mkdir(parents=True)
    installer.mkdir()
    outputs.mkdir()
    (source / "VERSION").write_text("1.2.13\n", encoding="utf-8")
    (source / "payload.txt").write_text("same bytes\n", encoding="utf-8")
    (source / "templates/demo/.devfleet/template.json").write_text('{"bootstrap_command":"./.devfleet/run.sh"}\n', encoding="utf-8")
    (source / "templates/demo/.devfleet/run.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (installer / "INSTALLER_VERSION").write_text("1.4.1\n", encoding="utf-8")
    artifact = outputs / "candidate.bin"
    artifact.write_bytes(b"candidate")
    return source, installer, artifact


def test_schema_v2_is_relocation_invariant_and_has_no_absolute_artifact_path(tmp_path: Path):
    source_a, installer_a, artifact_a = _tree(tmp_path / "checkout-a")
    shutil.copytree(tmp_path / "checkout-a", tmp_path / "different absolute checkout")
    source_b = tmp_path / "different absolute checkout/source"
    installer_b = tmp_path / "different absolute checkout/installer"
    artifact_b = tmp_path / "different absolute checkout/outputs/candidate.bin"
    first = build_fingerprint(source_a, installer_a, {"exe": artifact_a})
    second = build_fingerprint(source_b, installer_b, {"exe": artifact_b})
    assert first["releaseFingerprintId"] == second["releaseFingerprintId"]
    assert first["artifacts"] == [{"name": "exe", "bytes": 9, "sha256": first["artifacts"][0]["sha256"]}]
    assert "path" not in first["artifacts"][0]


def test_checkout_mode_noise_does_not_change_canonical_shipping_identity(tmp_path: Path):
    source, installer, artifact = _tree(tmp_path / "checkout")
    first = build_fingerprint(source, installer, {"tar": artifact})
    for path in (source / "payload.txt", source / "templates/demo/.devfleet/run.sh"):
        os.chmod(path, 0o755 if not (path.stat().st_mode & 0o111) else 0o644)
    second = build_fingerprint(source, installer, {"tar": artifact})
    assert first["releaseFingerprintId"] == second["releaseFingerprintId"]


def test_executable_contract_change_is_detected_but_non_executable_mode_noise_is_not(tmp_path: Path):
    source, installer, _ = _tree(tmp_path / "checkout")
    run = "templates/demo/.devfleet/run.sh"
    contracted = build_fingerprint(source, installer, source_executable_paths={run})
    non_executable = build_fingerprint(source, installer, source_executable_paths=set())
    assert contracted["releaseFingerprintId"] != non_executable["releaseFingerprintId"]
    run_entry = next(item for item in contracted["shippingInputs"] if item["root"] == "source" and item["path"] == run)
    assert run_entry["mode"] == "0755"


def test_artifact_byte_mutation_changes_release_id(tmp_path: Path):
    source, installer, artifact = _tree(tmp_path / "checkout")
    first = build_fingerprint(source, installer, {"exe": artifact})
    artifact.write_bytes(b"changed candidate")
    second = build_fingerprint(source, installer, {"exe": artifact})
    assert first["releaseFingerprintId"] != second["releaseFingerprintId"]


def test_release_pipeline_atomically_emits_current_tooling_schema_v2():
    script = (Path(__file__).parents[2] / "installer-source/Build-Release.ps1").read_text(encoding="utf-8")
    assert "releaseFingerprintSchemaVersion=2" in script
    assert "tooling-fingerprint-current.json" in script
    assert "Move-Item -LiteralPath $currentToolingTemporary" in script
    assert "toolingInputs=$fingerprintObject.toolingFingerprint.toolingInputs" in script
    assert "artifacts=$artifactRows" in script
