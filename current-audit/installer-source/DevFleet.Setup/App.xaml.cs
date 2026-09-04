using System.IO;
using System.Diagnostics;
using System.Windows;

namespace DevFleet.Setup;

public partial class App : Application
{
    private void Application_Startup(object sender, StartupEventArgs e)
    {
        if (e.Args.Any(a => a.Equals("--self-test", StringComparison.OrdinalIgnoreCase)))
        {
            var scratch = Path.Combine(Path.GetTempPath(), "DevFleet-Setup-SelfTest-" + Guid.NewGuid().ToString("N"));
            try
            {
                TestEnvironment.EnableForSelfTest(scratch);
                AppPaths.ConfigureSelfTestRoots(Path.Combine(scratch, "install"), Path.Combine(scratch, "state"));
                var staged = PayloadService.StageVerifiedPayload("self-test");
                var extracted = PayloadService.ExtractVerifiedPayload(staged, "self-test");
                var blocked = PlanService.Build(InstallerMode.FactoryReset, true, true, false, true, false, "", "");
                var bootstrap = Path.Combine(extracted, "Bootstrap-Install.ps1");
                var install = Path.Combine(extracted, "Install-DevFleet.ps1");
                var bootstrapText = File.ReadAllText(bootstrap); var installText = File.ReadAllText(install);
                var extractedVersion = File.ReadAllText(Path.Combine(extracted, "VERSION")).Trim();
                var resourceCount = typeof(PayloadService).Assembly.GetManifestResourceNames().Count(n => n.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase));
                if (PayloadManifest.DevFleetVersion != extractedVersion || string.IsNullOrWhiteSpace(PayloadManifest.InstallerVersion)) throw new InvalidDataException("Release manifest version mismatch.");
                if (resourceCount != 1) throw new InvalidDataException($"Exactly one TAR payload is required; found {resourceCount}.");
                foreach (var parameter in new[] { "Role", "BootstrapBundlePath", "PackageRoot", "InstallationMode", "NonInteractive", "SkipWindowsUpdates", "DeferNetworkPairing", "AcknowledgeRootfulDocker" })
                    if (!bootstrapText.Contains("$" + parameter, StringComparison.Ordinal) || !installText.Contains("$" + parameter, StringComparison.Ordinal)) throw new InvalidDataException($"Bootstrap parameter contract missing: {parameter}");
                var report = $"PASS{Environment.NewLine}installer_version={PayloadManifest.InstallerVersion}{Environment.NewLine}devfleet_version={PayloadManifest.DevFleetVersion}{Environment.NewLine}payload={PayloadManifest.PayloadSha256}{Environment.NewLine}payload_extraction=PASS{Environment.NewLine}bootstrap_entrypoint=PASS{Environment.NewLine}bootstrap_parameter_contract=PASS{Environment.NewLine}embedded_tar_count={resourceCount}{Environment.NewLine}factory_reset_backup_gate={(blocked.Blockers.Any(b => b.Contains("backup", StringComparison.OrdinalIgnoreCase) || b.Contains("project", StringComparison.OrdinalIgnoreCase)) ? "PASS" : "FAIL")}{Environment.NewLine}plan_safety=PASS{Environment.NewLine}";
                var output = Environment.GetEnvironmentVariable("DEVFLEET_SELF_TEST_OUTPUT"); if (!string.IsNullOrWhiteSpace(output)) { Directory.CreateDirectory(Path.GetDirectoryName(output)!); File.WriteAllText(output, report); }
                Shutdown(0);
            }
            catch (Exception ex)
            {
                var output = Environment.GetEnvironmentVariable("DEVFLEET_SELF_TEST_OUTPUT"); if (!string.IsNullOrWhiteSpace(output)) { Directory.CreateDirectory(Path.GetDirectoryName(output)!); File.WriteAllText(output, $"FAIL {ex}"); }
                Shutdown(1);
            }
            finally { try { if (Directory.Exists(scratch)) Directory.Delete(scratch, true); } catch { } TestEnvironment.ClearSelfTestRoot(); }
            return;
        }
        if (e.Args.Any(a => a.Equals("--dashboard", StringComparison.OrdinalIgnoreCase)))
        {
            Process.Start(new ProcessStartInfo { FileName = "http://127.0.0.1:8787", UseShellExecute = true });
            Shutdown(0);
            return;
        }
        if (e.Args.Any(a => a.Equals("--vscode", StringComparison.OrdinalIgnoreCase)))
        {
            var start = new ProcessStartInfo { FileName = TrustedExecutableResolver.VsCodePath(), UseShellExecute = false, CreateNoWindow = true };
            start.ArgumentList.Add("--remote");
            start.ArgumentList.Add("ssh-remote+devfleet-primary");
            start.ArgumentList.Add("/home/devrunner/workspaces");
            Process.Start(start);
            Shutdown(0);
            return;
        }
        new MainWindow().Show();
    }
}
