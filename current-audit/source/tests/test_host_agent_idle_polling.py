from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_host_agent_uses_adaptive_idle_polling():
    source = (ROOT / "windows/DevFleet-HostAgent.ps1").read_text(encoding="utf-8")
    assert "$pollMilliseconds=if($jobs.Count -gt 0){20}else{200}" in source
    assert "Start-Sleep -Milliseconds $pollMilliseconds" in source
