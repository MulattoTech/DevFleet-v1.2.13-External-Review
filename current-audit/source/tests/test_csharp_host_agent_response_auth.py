from pathlib import Path


ROOT = Path(__file__).parents[2]


def test_csharp_maintenance_client_authenticates_success_and_error_responses_before_trust():
    source = (ROOT / "installer-source/DevFleet.Setup/Services/InstallerLifecycle.cs").read_text(encoding="utf-8")
    assert source.count("VerifyResponseAuthentication(request, response, bodyBytes") >= 2
    assert source.index("VerifyResponseAuthentication(request, response, bodyBytes") < source.index("if (!response.IsSuccessStatusCode)")
    assert "CryptographicOperations.FixedTimeEquals" in source
    assert "response.StatusCode" in source
    assert "expectedHost" in source
    assert "request.RequestUri!.AbsolutePath" in source
    assert "X-DevFleet-Host-Response-Signature" in source


def test_host_agent_resets_auth_context_between_listener_requests():
    source = (ROOT / "source/windows/DevFleet-HostAgent.ps1").read_text(encoding="utf-8")
    assert "$context=$null;$auth=$null;$responseAuth=$null" in source
    assert "Send-AuthenticatedJsonResponse" in source
