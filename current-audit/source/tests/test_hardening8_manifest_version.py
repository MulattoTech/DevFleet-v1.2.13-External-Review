import re
from pathlib import Path

from _bundle_layout import resolve_bundle_layout


ROOT = Path(__file__).parents[2]
LAYOUT = resolve_bundle_layout(Path(__file__))


def test_application_manifest_tracks_canonical_installer_four_part_version():
    installer_version = (ROOT / "installer-source/INSTALLER_VERSION").read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"\d+\.\d+\.\d+", installer_version)
    manifest = (ROOT / "installer-source/DevFleet.Setup/app.manifest").read_text(encoding="utf-8")
    identity = re.search(r'<assemblyIdentity\s+version="([^"]+)"\s+name="MTechLabs\.DevFleet\.Setup"', manifest)
    assert identity
    assert identity.group(1) == f"{installer_version}.0"


def test_release_builder_derives_and_verifies_manifest_identity():
    build = (ROOT / "installer-source/Build-Release.ps1").read_text(encoding="utf-8")
    assert '$assemblyVersion="$installerVersion.0"' in build
    assert "Windows application manifest identity is not synchronized" in build


def test_ai_bundle_requires_current_schema_v2_identity_closure():
    builder = (LAYOUT.release_tooling_root / "Build-AIAuditBundle.ps1").read_text(encoding="utf-8")
    validator = (ROOT / "source/tools/validate_ai_audit_bundle.py").read_text(encoding="utf-8")
    for name in ("release-fingerprint.json", "tooling-fingerprint-current.json", "final-artifact-hashes.json"):
        assert name in builder
        assert name in validator
    assert "validate_audit_coherence.py" in builder
    assert "validate_audit_coherence.py" in validator
