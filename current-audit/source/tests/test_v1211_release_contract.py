from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_connected_bootstrap_parameter_contract_matches_installer():
    bootstrap = (ROOT / "Bootstrap-Install.ps1").read_text(encoding="utf-8")
    install = (ROOT / "Install-DevFleet.ps1").read_text(encoding="utf-8")
    for parameter in ("Role", "BootstrapBundlePath", "PackageRoot", "InstallationMode", "NonInteractive", "SkipWindowsUpdates", "DeferNetworkPairing"):
        assert f"${parameter}" in bootstrap
        assert f"${parameter}" in install
    assert "-InstallationMode',$InstallationMode" in bootstrap
    assert "-PackageRoot',$packageRoot" in bootstrap
    assert "'Connected'" in bootstrap


def test_clean_pc_bootstrap_uses_official_signed_powershell_release():
    bootstrap = (ROOT / "Bootstrap-Install.ps1").read_text(encoding="utf-8")
    manifest = (ROOT / "dependencies.json").read_text(encoding="utf-8")
    assert "dependencies.json" in bootstrap
    assert "api.github.com/repos/PowerShell/PowerShell/releases/latest" in manifest
    assert "Save-AllowlistedHttpsDownload" in bootstrap
    assert "Test-OfficialSigner" in bootstrap
    assert "curl.exe -L" not in bootstrap
    assert "SignerCertificate.Subject -notmatch" not in bootstrap
    assert "DevFleet.Common.psm1" in bootstrap
    assert "winget" not in bootstrap.lower()


def test_bootstrap_validates_power_shell_asset_filename_not_full_url_path():
    bootstrap = (ROOT / "Bootstrap-Install.ps1").read_text(encoding="utf-8")
    assert "$assetName=[IO.Path]::GetFileName($assetUri.AbsolutePath)" in bootstrap
    assert "$assetName -ne [string]$asset.name" in bootstrap


def test_version_source_propagates_to_linux_metadata_without_stale_fallback():
    assert (ROOT / "VERSION").read_text(encoding="utf-8").strip() == "1.2.13"
    linux = (ROOT / "linux" / "bootstrap-compute.sh").read_text(encoding="utf-8")
    provision = (ROOT / "windows" / "02-Provision-ComputeNode.ps1").read_text(encoding="utf-8")
    assert "PackageVersion" in provision
    assert "PACKAGE_VERSION=$(JQ .PackageVersion)" in linux
    # Metadata is serialized with jq rather than raw shell interpolation so
    # quotes, newlines, and shell-like values cannot alter the JSON structure.
    assert "jq -n" in linux
    assert '--arg version "$PACKAGE_VERSION"' in linux
    assert 'package_version:$version' in linux
    assert '"package_version":"1.1.0"' not in linux
    assert '"package_version":"1.2.6"' not in linux


def test_dependency_manifest_has_one_canonical_source_and_generated_installer_copy():
    assert not (ROOT.parent / "installer-source" / "dependencies.json").exists()
    prepare = (ROOT.parent / "installer-source" / "Prepare-ReleaseInputs.ps1").read_text(encoding="utf-8")
    assert "$sourceDependencies = Join-Path $Source 'dependencies.json'" in prepare
    assert "Copy-Item -LiteralPath $sourceDependencies -Destination $installerDependencies -Force" in prepare
    assert "Installer dependency manifest is not byte-identical" in prepare


def test_as_invoker_self_test_registers_its_exact_temp_root_before_staging():
    manifest = (ROOT.parent / "installer-source" / "DevFleet.Setup" / "app.manifest").read_text(encoding="utf-8")
    app = (ROOT.parent / "installer-source" / "DevFleet.Setup" / "App.xaml.cs").read_text(encoding="utf-8")
    services = (ROOT.parent / "installer-source" / "DevFleet.Setup" / "Services" / "InstallerServices.cs").read_text(encoding="utf-8")
    enable = "TestEnvironment.EnableForSelfTest(scratch);"
    stage = 'PayloadService.StageVerifiedPayload("self-test")'
    assert 'requestedExecutionLevel level="asInvoker"' in manifest
    assert enable in app and stage in app
    assert app.index(enable) < app.index(stage)
    assert 'Guid.TryParseExact(leaf[prefix.Length..], "N", out _)' in services
    assert "TestEnvironment.IsAuthorizedSelfTestPath(path)" in services
    assert "WindowsIdentity.GetCurrent().User" in services
    assert 'new FileSystemAccessRule("BUILTIN\\\\Users"' not in services
    assert 'new FileSystemAccessRule("NT AUTHORITY\\\\Authenticated Users"' not in services
    assert 'new FileSystemAccessRule("Everyone"' not in services


def test_multipass_readiness_uses_structured_status_and_one_absolute_deadline():
    common = (ROOT / "windows" / "DevFleet.Common.psm1").read_text(encoding="utf-8")
    assert "cloud-init status --format=json" in common
    assert "ConvertFrom-Json" in common
    assert "[DateTime]::UtcNow" in common
    assert "Start-Sleep -Milliseconds" in common
    assert "cloud-init status --wait" not in common
    assert "x1B" in common


def test_connected_dependency_installers_are_bounded_and_fail_over_to_official_source():
    common = (ROOT / "windows" / "DevFleet.Common.psm1").read_text(encoding="utf-8")
    prereqs = (ROOT / "windows" / "01-Install-Prerequisites.ps1").read_text(encoding="utf-8")
    assert "Invoke-External -FilePath $health.Path" in common
    assert "-TimeoutSeconds 600" in common
    assert "-AllowedExitCodes @(0,-1978335189)" in common
    assert "Invoke-External -FilePath $msiexec" in common
    assert "Invoke-External -FilePath $path" in common
    assert "External command timed out" in prereqs
    assert "Install-OfficialDependency -Dependency $dependency" in prereqs


def test_connected_dependency_probes_and_official_downloads_have_network_deadlines():
    common = (ROOT / "windows" / "DevFleet.Common.psm1").read_text(encoding="utf-8")
    assert "ArgumentList @('--version') -TimeoutSeconds 60" in common
    assert "ArgumentList @('source','list','--disable-interactivity') -TimeoutSeconds 60" in common
    assert "ArgumentList @('search','--id','Microsoft.PowerShell','--exact','--source','winget','--disable-interactivity') -TimeoutSeconds 60" in common
    assert "Invoke-RestMethod -UseBasicParsing -TimeoutSec 60" in common
    assert "Invoke-WebRequest -UseBasicParsing -TimeoutSec 60" in common
    assert "$client.Timeout=[TimeSpan]::FromSeconds(60)" in common


def test_install_defers_node_identity_until_after_reboot_gate():
    install = (ROOT / "Install-DevFleet.ps1").read_text(encoding="utf-8")
    identity = "$nodeIdentity = Get-OrCreateNodeIdentity -Role $Role"
    secrets = "Get-OrCreateSecrets | Out-Null"
    assert install.count(identity) == 1
    assert install.count(secrets) == 1
    assert install.index(secrets) < install.index(identity)
    assert install.index("if (Test-PendingReboot)") < install.index(identity)
