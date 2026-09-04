from pathlib import Path
import json


ROOT = Path(__file__).resolve().parents[1]


def test_powershell_dependency_probe_authenticates_before_version_execution():
    source = (ROOT / "windows" / "DevFleet.Common.psm1").read_text(encoding="utf-8")
    assert "Get-AuthenticodeSignature" in source
    assert "while($cursor)" in source
    assert "ReparsePoint" in source
    assert "allowedSignerSubjectsExact" in source
    assert "Legacy substring signer policy is rejected" in source
    assert "Get-TrustedDependencyCandidates $Dependency" in source
    assert "if($signature.Status -ne 'Valid' -and -not $allowUnsignedInstalled)" in source
    assert "Get-Acl -LiteralPath $full" in source
    assert "if(@($exact).Count -gt 0" in source
    assert "$policy=if($null -ne $Dependency){$Dependency.installerAuthenticityPolicy}else{$null}" in source
    assert "PSObject.Properties['installedExecutableTrust']" in source


def test_canonical_dependency_policies_do_not_use_substring_signer_authority():
    for relative in ("dependencies.json",):
        for path in (ROOT / relative, ROOT.parent / "installer-source" / "DevFleet.Setup" / relative):
            manifest = json.loads(path.read_text(encoding="utf-8"))
            policies = [item["installerAuthenticityPolicy"] for item in manifest["dependencies"]]
            assert all("allowedSignerPatterns" not in policy for policy in policies)
            assert all(policy.get("strategy") == "VendorReleaseSha256" or policy.get("allowedSignerSubjectsExact") for policy in policies)
            multipass = next(item for item in manifest["dependencies"] if item["id"] == "multipass")
            assert multipass["installerAuthenticityPolicy"]["installedExecutableTrust"] == "signed-installer-locked-path"


def test_multipass_runtime_resolution_reuses_canonical_dependency_policy():
    source = (ROOT / "windows" / "DevFleet.Common.psm1").read_text(encoding="utf-8")
    start = source.index("function Get-MultipassExe")
    end = source.index("function Assert-MultipassIsolation", start)
    resolver = source[start:end]
    assert "Get-CanonicalDependencyManifest -PackageRoot $packageRoot" in resolver
    assert "Where-Object id -eq 'multipass'" in resolver
    assert "Get-DependencyStatus -Dependency $dependency" in resolver
    assert "Status -eq 'Compatible'" in resolver
    # The resolver must never fall back to the generic no-policy trust check.
    assert "Test-TrustedExecutableCandidate $candidate" not in resolver


def test_csharp_dependency_probe_authenticates_before_reading_version():
    source = (ROOT.parent / "installer-source" / "DevFleet.Setup" / "Services" / "InstallerLifecycle.cs").read_text(encoding="utf-8")
    assert "IsTrustedInstalledDependency(candidate, dependency)" in source
    assert "ReadAuthenticodeSubject" in source
    assert "AllowedSignerSubjectsExact" in source
    assert "Legacy substring signer policy is rejected" in source
    assert source.index("IsTrustedInstalledDependency(candidate, dependency)") < source.index("ReadVersion(candidate, dependency)")
    assert "DirectoryInfo(Path.GetDirectoryName(full)!)" in source
    assert "InstalledExecutableTrust" in source
    assert "signed-installer-locked-path" in source
    assert "Microsoft.DesktopAppInstaller" in source
    assert "8wekyb3d8bbwe" in source


def test_secret_bearing_archive_arguments_are_not_created():
    source = (ROOT / "windows" / "DevFleet.Common.psm1").read_text(encoding="utf-8")
    assert "-p$password" not in source
    assert "New-EncryptedBundle" in source
    assert "Expand-EncryptedBundle" in source
    assert "DFENV001" in source
    assert "AesGcm" in source


def test_external_process_wrapper_has_timeout_tree_kill_and_bounded_diagnostics():
    source = (ROOT / "windows" / "DevFleet.Common.psm1").read_text(encoding="utf-8")
    assert "TimeoutSeconds" in source
    assert "$process.Kill($true)" in source
    assert "MaxDiagnosticChars" in source
    assert "EvidenceLogPath" in source


def test_windows_powershell_common_module_has_no_powershell_7_null_coalescing_operator():
    source = (ROOT / "windows" / "DevFleet.Common.psm1").read_text(encoding="utf-8")
    assert "??" not in source
    assert "Add-Type -AssemblyName System.Net.Http" in source
    assert "[System.Net.Http.HttpClientHandler]::new()" in source
    assert "[System.Net.Http.HttpClient]::new($handler)" in source
