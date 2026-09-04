from pathlib import Path


ROOT = Path(__file__).parents[2]


def test_installer_self_cleanup_uses_argument_bound_helper_without_cmd_shell():
    source = (ROOT / "installer-source/DevFleet.Setup/Services/InstallerLifecycle.cs").read_text(encoding="utf-8")
    method = source[source.index("private static void ScheduleSelfRemoval"):source.index("private static void RemoveExactRegistryEntry")]
    assert ".cmd" not in method
    assert "cmd.exe" not in method
    assert "ArgumentList.Add" in method
    assert "-LiteralPath $Target" in method
    assert "ProcessWindowStyle.Hidden" in method
    assert "Start-Sleep -Milliseconds 500" in method
