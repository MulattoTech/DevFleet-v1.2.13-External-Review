from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "compute_shipping_input_identity.py"


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def _fixture(tmp_path: Path) -> tuple[Path, str, dict[str, Path]]:
    repo = tmp_path / "repo"
    (repo / "source" / "tools").mkdir(parents=True)
    (repo / "installer-source").mkdir()
    (repo / "tools").mkdir()
    (repo / "automation").mkdir()
    (repo / "outputs").mkdir()
    shutil.copy2(ROOT / "source" / "tools" / "release_fingerprint.py", repo / "source" / "tools" / "release_fingerprint.py")
    shutil.copy2(ROOT / "source" / "tools" / "hook_modes.py", repo / "source" / "tools" / "hook_modes.py")
    (repo / "source" / "VERSION").write_bytes(b"1.2.13\n")
    (repo / "source" / "payload.txt").write_bytes(b"alpha\nbeta\n")
    (repo / "installer-source" / "INSTALLER_VERSION").write_bytes(b"1.4.1\n")
    (repo / "installer-source" / "payload.ps1").write_bytes(b"Write-Output ok\n")
    (repo / "tools" / "release-tool.txt").write_text("one\n", encoding="utf-8")
    (repo / "automation" / "runner.txt").write_text("one\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    _git(repo, "config", "user.email", "devfleet-test@example.invalid")
    _git(repo, "config", "user.name", "DevFleet Test")
    _git(repo, "config", "core.autocrlf", "false")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "candidate")
    commit = _git(repo, "rev-parse", "HEAD")
    artifacts = {
        "exe": repo / "outputs" / "candidate.exe",
        "tar": repo / "outputs" / "candidate.tar.gz",
        "portable": repo / "outputs" / "candidate-portable.zip",
        "installerSource": repo / "outputs" / "candidate-installer.zip",
    }
    for index, path in enumerate(artifacts.values(), 1):
        path.write_bytes((f"artifact-{index}\n").encode())
    return repo, commit, artifacts


def _run(repo: Path, commit: str, artifacts: dict[str, Path]) -> dict[str, object]:
    command = [sys.executable, str(SCRIPT), "--workspace", str(repo), "--candidate-commit", commit]
    for name, path in artifacts.items():
        command.extend(["--artifact", f"{name}={path}"])
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def test_candidate_rows_ignore_crlf_checkout_and_tooling_moves(tmp_path: Path) -> None:
    repo, commit, artifacts = _fixture(tmp_path)
    baseline = _run(repo, commit, artifacts)
    (repo / "source" / "payload.txt").write_bytes(b"alpha\r\nbeta\r\n")
    (repo / "tools" / "release-tool.txt").write_text("two\n", encoding="utf-8")
    changed = _run(repo, commit, artifacts)

    assert changed["candidateShippingInputIdentity"] == baseline["candidateShippingInputIdentity"]
    assert changed["candidateReleaseFingerprintId"] == baseline["candidateReleaseFingerprintId"]
    assert changed["liveShippingInputIdentity"] != changed["candidateShippingInputIdentity"]
    assert changed["lineEndingComparison"] == "CRLF_ONLY"
    assert changed["crlfOnlyPaths"] == ["source/payload.txt"]
    assert changed["candidateFingerprint"]["shippingInputs"] == baseline["candidateFingerprint"]["shippingInputs"]
    assert changed["liveToolingFingerprint"]["toolingFingerprintId"] != baseline["liveToolingFingerprint"]["toolingFingerprintId"]
    assert "toolingFingerprint" not in changed["candidateFingerprint"]


def test_candidate_release_fingerprint_binds_exact_artifact_tuple(tmp_path: Path) -> None:
    repo, commit, artifacts = _fixture(tmp_path)
    baseline = _run(repo, commit, artifacts)
    artifacts["exe"].write_bytes(b"changed-exe\n")
    changed = _run(repo, commit, artifacts)
    assert changed["candidateShippingInputIdentity"] == baseline["candidateShippingInputIdentity"]
    assert changed["candidateReleaseFingerprintId"] != baseline["candidateReleaseFingerprintId"]
    assert changed["candidateFingerprint"]["artifacts"] != baseline["candidateFingerprint"]["artifacts"]


def test_partial_artifact_tuple_fails_closed(tmp_path: Path) -> None:
    repo, commit, artifacts = _fixture(tmp_path)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--workspace", str(repo), "--candidate-commit", commit, "--artifact", f"exe={artifacts['exe']}"],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "artifact tuple must be exactly" in result.stderr
