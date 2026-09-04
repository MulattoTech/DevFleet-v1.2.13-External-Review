from pathlib import Path


ROOT = Path(__file__).parents[1]
REPO = ROOT.parent


def test_host_agent_install_has_ledger_bound_exact_windows_integrations():
    install = (ROOT / "windows/Install-DevFleet-HostAgent.ps1").read_text(encoding="utf-8")
    removal = (ROOT / "windows/Remove-DevFleet-OwnedIntegrations.ps1").read_text(encoding="utf-8")
    ownership = (ROOT / "windows/DevFleet-WindowsIntegrationOwnership.psm1").read_text(encoding="utf-8")

    assert "DevFleet Host Agent 8790*" not in install
    assert "Get-NetFirewallRule -DisplayName 'DevFleet Host Agent" not in install
    assert "-AdoptLegacyDevFleetIntegrations" in install
    assert "WINDOWS INTEGRATION OWNERSHIP CONFLICT" in install
    assert "InstallationGeneration" in install
    assert "ScheduledTasks=@($taskBinding)" in install
    assert "FirewallRules=@($firewallBindings)" in install
    assert "Services=@()" in install
    assert "Assert-DevFleetTaskBinding" in install
    assert "Assert-DevFleetFirewallBinding" in install
    assert "Remove-NetFirewallRule -DisplayName" not in removal
    assert "Get-NetFirewallRule -Name" in removal
    assert "Assert-DevFleetServiceBinding" in removal
    assert "Stop-Service -Name" in removal and "Stop-Service -Name ([string]$binding.Name) -Force" not in removal
    assert "Assert-DevFleetExactFields" in ownership


def test_installer_cleanup_requires_extended_ownership_ledger():
    services = (REPO / "installer-source/DevFleet.Setup/Services/InstallerServices.cs").read_text(encoding="utf-8")
    lifecycle = (REPO / "installer-source/DevFleet.Setup/Services/InstallerLifecycle.cs").read_text(encoding="utf-8")

    assert "List<OwnedWindowsIntegration> WindowsIntegrations" in services
    assert "WindowsIntegrationOwnershipPath" in services
    assert "InstallationGeneration" in services
    assert "same-name foreign resources were preserved" in lifecycle
    assert "Remove-DevFleet-OwnedIntegrations.ps1" in lifecycle
    assert "Get-ScheduledTask -TaskName 'DevFleet Host Agent'" not in lifecycle
    assert "Remove-NetFirewallRule -DisplayName" not in lifecycle
    assert "sc.exe delete DevFleetHostAgent" not in lifecycle


def test_authenticated_protocol_accepts_empty_get_and_response_bodies_without_relaxing_auth():
    protocol = (ROOT / "windows/DevFleet-HostAgentProtocol.psm1").read_text(encoding="utf-8")
    assert "[AllowEmptyCollection()][byte[]]$Body" in protocol
    assert "New-HostAgentRequestAuthentication $Method $path $bodyBytes $Key $ExpectedHost" in protocol
    assert "Test-HostAgentResponseAuthentication $Method $path $status $responseBody $Key $ExpectedHost" in protocol
    assert "X-DevFleet-Host-Expected" in protocol
    assert "CryptographicOperations]::FixedTimeEquals" in protocol
