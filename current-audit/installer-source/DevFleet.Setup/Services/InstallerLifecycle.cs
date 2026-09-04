using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Threading;
using Microsoft.Win32;

namespace DevFleet.Setup;

public sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError, bool OutputComplete = true);
public sealed record ProcessInvocation(string FileName, IReadOnlyList<string> Arguments, string? WorkingDirectory);

public static class DeadlinePolicy
{
    public const string Version = "1.0.0";
    public const int TransactionTerminalizationMarginSeconds = 600;
    public const int BootstrapSeconds = 240;
    public const int PreflightSeconds = 120;
    public const int PrerequisiteDependencyCount = 6;
    public const int DependencyProbeSeconds = 60;
    public const int DependencyHealthSeconds = 180;
    public const int DependencyInstallSeconds = 1800;
    public const int DependencyVerificationSeconds = 60;
    public const int WindowsCapabilitySeconds = 900;
    public const int WindowsFeatureSeconds = 900;
    public const int MultipassConfigurationSeconds = 600;
    public const int VsCodeExtensionSeconds = 300;
    public static int PrerequisitesSeconds => PrerequisiteDependencyCount * (DependencyProbeSeconds + DependencyHealthSeconds + DependencyInstallSeconds + DependencyVerificationSeconds) + WindowsCapabilitySeconds + WindowsFeatureSeconds + (4 * MultipassConfigurationSeconds) + (3 * VsCodeExtensionSeconds);
    public const int WindowsTailscaleSeconds = 180;
    public const int HostAgentSeconds = 300;
    public const int MultipassLaunchSeconds = 900;
    public const int MultipassReadinessSeconds = 1200;
    public const int PayloadTransferSeconds = 900;
    public const int GuestBootstrapPackagePrerequisitesSeconds = 900;
    public const int GuestBootstrapDockerRepositoryAndInstallSeconds = 1200;
    public const int GuestBootstrapTailscaleRepositoryAndInstallSeconds = 1200;
    public const int GuestBootstrapRootlessRuntimeSeconds = 600;
    public const int GuestBootstrapNodeToolchainSeconds = 600;
    public const int GuestBootstrapPythonRuntimeSeconds = 1200;
    public const int GuestBootstrapServiceAndFirewallFinalizationSeconds = 600;
    public static int GuestBootstrapSeconds => GuestBootstrapPackagePrerequisitesSeconds + GuestBootstrapDockerRepositoryAndInstallSeconds + GuestBootstrapTailscaleRepositoryAndInstallSeconds + GuestBootstrapRootlessRuntimeSeconds + GuestBootstrapNodeToolchainSeconds + GuestBootstrapPythonRuntimeSeconds + GuestBootstrapServiceAndFirewallFinalizationSeconds;
    public const int SshAndMarkerSeconds = 300;
    public const int VaultSnapshotSeconds = 300;
    public const int TailscaleSeconds = 900;
    public const int VaultClientSeconds = 300;
    public const int ShortcutsSeconds = 180;
    public const int ExportSeconds = 300;
    public const int VerificationSeconds = 300;

    public static int ComputeStageSeconds => MultipassLaunchSeconds + MultipassReadinessSeconds + PayloadTransferSeconds + GuestBootstrapSeconds + SshAndMarkerSeconds;
    public static int VaultStageSeconds => VaultSnapshotSeconds + MultipassLaunchSeconds + MultipassReadinessSeconds + PayloadTransferSeconds + GuestBootstrapSeconds + SshAndMarkerSeconds;
    public static int DesktopTransactionSeconds => BootstrapSeconds + PreflightSeconds + PrerequisitesSeconds + WindowsTailscaleSeconds + HostAgentSeconds + ComputeStageSeconds + TailscaleSeconds + ShortcutsSeconds + ExportSeconds + VerificationSeconds + TransactionTerminalizationMarginSeconds;
    public static int LaptopTransactionSeconds => BootstrapSeconds + PreflightSeconds + PrerequisitesSeconds + WindowsTailscaleSeconds + HostAgentSeconds + ComputeStageSeconds + VaultStageSeconds + (TailscaleSeconds * 2) + VaultClientSeconds + ShortcutsSeconds + ExportSeconds + VerificationSeconds + TransactionTerminalizationMarginSeconds;

    public static int GetConnectedTransactionBudgetSeconds(string role) => role.Contains("Laptop", StringComparison.OrdinalIgnoreCase) ? LaptopTransactionSeconds : DesktopTransactionSeconds;
}

public interface IProcessRunner
{
    ProcessResult Run(string fileName, IReadOnlyList<string> arguments, string? workingDirectory = null);
    Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, string? workingDirectory = null, CancellationToken cancellationToken = default)
        => Task.Run(() => Run(fileName, arguments, workingDirectory), cancellationToken);
}

public sealed class ProcessRunner : IProcessRunner
{
    public int DefaultTimeoutSeconds { get; }
    public bool AllowEnvironmentOverride { get; }

    public ProcessRunner(int defaultTimeoutSeconds = 900, bool allowEnvironmentOverride = true)
    {
        if (defaultTimeoutSeconds <= 0) throw new ArgumentOutOfRangeException(nameof(defaultTimeoutSeconds));
        DefaultTimeoutSeconds = defaultTimeoutSeconds;
        AllowEnvironmentOverride = allowEnvironmentOverride;
    }

    public ProcessResult Run(string fileName, IReadOnlyList<string> arguments, string? workingDirectory = null)
        => RunAsync(fileName, arguments, workingDirectory).GetAwaiter().GetResult();

    public async Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, string? workingDirectory = null, CancellationToken cancellationToken = default)
    {
        using var process = new Process { StartInfo = new ProcessStartInfo
        {
            FileName = fileName,
            WorkingDirectory = workingDirectory ?? Environment.CurrentDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        } };
        foreach (var argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        process.Start();
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        var timeoutSeconds = AllowEnvironmentOverride && int.TryParse(Environment.GetEnvironmentVariable("DEVFLEET_SETUP_PROCESS_TIMEOUT_SECONDS"), out var configured) && configured > 0 ? configured : DefaultTimeoutSeconds;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            var exitCode = process.ExitCode;
            try { await Task.WhenAll(stdoutTask, stderrTask).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false); }
            catch (TimeoutException) { }
            var outputComplete = stdoutTask.Status == TaskStatus.RanToCompletion && stderrTask.Status == TaskStatus.RanToCompletion;
            return new ProcessResult(
                exitCode,
                stdoutTask.Status == TaskStatus.RanToCompletion ? stdoutTask.Result : "",
                stderrTask.Status == TaskStatus.RanToCompletion ? stderrTask.Result : "",
                outputComplete);
        }
        catch (OperationCanceledException)
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
            try { await Task.WhenAll(stdoutTask, stderrTask).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false); } catch { }
            var outputComplete = stdoutTask.Status == TaskStatus.RanToCompletion && stderrTask.Status == TaskStatus.RanToCompletion;
            return new ProcessResult(-2, stdoutTask.Status == TaskStatus.RanToCompletion ? stdoutTask.Result : "", $"Process timed out after {timeoutSeconds}s. { (stderrTask.Status == TaskStatus.RanToCompletion ? stderrTask.Result : "") }", outputComplete);
        }
    }
}

public sealed class RecordingProcessRunner : IProcessRunner
{
    private readonly Queue<ProcessResult> _results = new();
    public List<ProcessInvocation> Invocations { get; } = [];
    public void QueueResult(ProcessResult result) => _results.Enqueue(result);
    public ProcessResult Run(string fileName, IReadOnlyList<string> arguments, string? workingDirectory = null)
    {
        Invocations.Add(new ProcessInvocation(fileName, arguments, workingDirectory));
        return _results.Count > 0 ? _results.Dequeue() : new ProcessResult(0, "fixture success", "");
    }
}

public interface IFileSystem
{
    bool FileExists(string path);
    void CopyFile(string source, string destination, bool overwrite);
    void DeleteFile(string path);
    IReadOnlyList<string> EnumerateFiles(string root);
}

public sealed class RealFileSystem : IFileSystem
{
    public bool FileExists(string path) => File.Exists(path);
    public void CopyFile(string source, string destination, bool overwrite) { Directory.CreateDirectory(Path.GetDirectoryName(destination)!); File.Copy(source, destination, overwrite); }
    public void DeleteFile(string path) { if (File.Exists(path)) File.Delete(path); }
    public IReadOnlyList<string> EnumerateFiles(string root) => Directory.Exists(root) ? Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).ToArray() : [];
}

public interface IRegistryManager { void RemoveExact(string key); }
public interface IServiceManager { bool IsHealthy(string serviceName); void StopOwned(string serviceName); }
public interface IShortcutManager { void RemoveExact(string path); }
public interface IFirewallManager { void RemoveExact(string ruleName); }
public interface ISshManager { void RemoveManagedBlock(string marker); }
public interface IVsCodeManager { void RemoveManagedAlias(string alias); }
public interface IDependencyInstaller { DependencyResult VerifyAndInstall(string dependencyRoot); }

public sealed record DependencyResult(bool Available, bool InstalledByDevFleet, bool RebootRequired, string Detail);

public sealed class DependencyDefinition
{
    public string Id { get; init; } = "";
    public string DisplayName { get; init; } = "";
    public string Classification { get; init; } = "OPTIONAL";
    public bool Required { get; init; }
    public string[] Roles { get; init; } = [];
    public string[] Features { get; init; } = [];
    public string MinimumSupportedVersion { get; init; } = "0.0.0";
    public int? MaximumMajor { get; init; }
    public string[] ExecutableProbes { get; init; } = [];
    public string[] RegistryProbes { get; init; } = [];
    public string[] AppPathsProbes { get; init; } = [];
    public string[] KnownVendorInstallLocations { get; init; } = [];
    public string? WingetPackageId { get; init; }
    public OfficialResolver DirectOfficialVendorResolver { get; init; } = new();
    public InstallerAuthenticityPolicy InstallerAuthenticityPolicy { get; init; } = new();
    public string[] SilentInstallArguments { get; init; } = [];
    public string RebootSemantics { get; init; } = "0";
    public VersionProbe VersionProbe { get; init; } = new();
    public string PostInstallExecutableDiscovery { get; init; } = "rediscover from all supported probes";
    public string PostInstallVersionVerification { get; init; } = "verify installed version";

    // Compatibility aliases retained for existing installer UI/tests while the manifest is canonical.
    public string Name => DisplayName;
    public string Executable => ExecutableProbes.FirstOrDefault() ?? "";
    public Version MinimumVersion => Version.TryParse(MinimumSupportedVersion, out var v) ? v : new Version(0, 0);
    public string WingetId => WingetPackageId ?? "";
    public Uri OfficialMetadata => new(DirectOfficialVendorResolver.MetadataUri);
}

public sealed class OfficialResolver
{
    public string Type { get; init; } = "";
    public string MetadataUri { get; init; } = "https://example.invalid/";
    public string? OfficialPageUri { get; init; }
    public string? DirectUri { get; init; }
    public string? ExpectedOwner { get; init; }
    public string? ExpectedRepository { get; init; }
    public string[] AllowedHosts { get; init; } = [];
    public string? AssetRegex { get; init; }
    public string? OfficialPageAssetRegex { get; init; }
}

public sealed class InstallerAuthenticityPolicy
{
    public string Strategy { get; init; } = "Authenticode";
    public bool Required { get; init; }
    public string[] AllowedSignerPatterns { get; init; } = [];
    public string[] AllowedSignerSubjectsExact { get; init; } = [];
    public string InstalledExecutableTrust { get; init; } = "signed-executable";
    public string[] Extensions { get; init; } = [];
}

public static class SignerIdentity
{
    public static string NormalizeSubject(string subject)
    {
        if (string.IsNullOrWhiteSpace(subject)) return "";
        try
        {
            var formatted = new X500DistinguishedName(subject).Format(false);
            return Regex.Replace(formatted, @"\s+", "").Trim().ToUpperInvariant();
        }
        catch { return Regex.Replace(subject, @"\s+", "").Trim().ToUpperInvariant(); }
    }

    public static bool MatchesExact(string subject, IEnumerable<string> expected)
        => expected.Any(value => NormalizeSubject(subject).Equals(NormalizeSubject(value), StringComparison.Ordinal));
}

public static class VendorReleaseAuthenticity
{
    public static string NormalizeDigest(string digest)
    {
        var normalized = (digest ?? "").Trim();
        if (normalized.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)) normalized = normalized[7..];
        if (!Regex.IsMatch(normalized, "^[0-9a-fA-F]{64}$")) throw new InvalidDataException("Vendor release digest must be a SHA-256 value.");
        return normalized.ToLowerInvariant();
    }

    public static string VerifySha256(string path, string expectedDigest)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("Vendor release artifact is missing.", path);
        var expected = NormalizeDigest(expectedDigest);
        using var stream = File.OpenRead(path);
        var actual = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException($"Vendor release SHA-256 mismatch for {Path.GetFileName(path)}: expected {expected}, got {actual}.");
        return actual;
    }
}

public sealed class VersionProbe
{
    public string[] Arguments { get; init; } = ["--version"];
    public string? Regex { get; init; } = @"(?<!\d)(\d+\.\d+(?:\.\d+){0,2})";
}

public sealed class DependencyManifestDocument
{
    public int SchemaVersion { get; init; }
    public string ManifestVersion { get; init; } = "";
    public string SupportedProfile { get; init; } = "";
    public List<DependencyDefinition> Dependencies { get; init; } = [];
}

public sealed record DependencyDetection(string Name, bool Found, string ExecutablePath, Version? Version, bool Compatible, string Source, string Classification)
{
    public string Status => !Found ? "Missing" : Version is null ? "Broken" : Compatible ? "Compatible" : "Outdated";
}
public sealed record WingetHealth(string Status, string ExecutablePath, string Version, string Detail);
public sealed record TailscaleAuthentication(string State, Uri? AuthenticationUri, string Detail, bool TimedOut = false);

public sealed record InstallStage(string Name, string Script, IReadOnlyList<string> Roles);

public static class InstallerStageCatalog
{
    public static IReadOnlyList<InstallStage> ForRole(string role)
    {
        if (role.Contains("Laptop", StringComparison.OrdinalIgnoreCase))
            return [
                new("Preflight", "windows/00-Preflight.ps1", ["Laptop"]),
                new("Prerequisites", "windows/01-Install-Prerequisites.ps1", ["Laptop"]),
                new("Windows Tailscale", "windows/04a-Connect-WindowsTailscale.ps1", ["Laptop"]),
                new("Host Agent", "windows/Install-DevFleet-HostAgent.ps1", ["Laptop"]),
                new("Failover compute", "windows/02-Provision-ComputeNode.ps1", ["Laptop"]),
                new("Vault", "windows/03-Provision-Vault.ps1", ["Laptop"]),
                new("Failover Tailscale", "windows/04-Connect-Tailscale.ps1", ["Laptop"]),
                new("Vault client", "windows/05-Configure-LocalVaultClient.ps1", ["Laptop"]),
                new("Shortcuts", "windows/08-Install-Shortcuts.ps1", ["Laptop"]),
                new("Laptop bootstrap export", "windows/09-Export-Laptop-Bootstrap.ps1", ["Laptop"]),
                new("Verification", "windows/Test-DevFleet.ps1", ["Laptop"])
            ];
        if (role.Contains("Desktop", StringComparison.OrdinalIgnoreCase) || role.Contains("Primary", StringComparison.OrdinalIgnoreCase))
            return [
                new("Preflight", "windows/00-Preflight.ps1", ["Desktop"]),
                new("Prerequisites", "windows/01-Install-Prerequisites.ps1", ["Desktop"]),
                new("Windows Tailscale", "windows/04a-Connect-WindowsTailscale.ps1", ["Desktop"]),
                new("Host Agent", "windows/Install-DevFleet-HostAgent.ps1", ["Desktop"]),
                new("Primary compute", "windows/02-Provision-ComputeNode.ps1", ["Desktop"]),
                new("Primary Tailscale", "windows/04-Connect-Tailscale.ps1", ["Desktop"]),
                new("Shortcuts", "windows/08-Install-Shortcuts.ps1", ["Desktop"]),
                new("Desktop pairing export", "windows/10-Export-Desktop-Pairing.ps1", ["Desktop"]),
                new("Verification", "windows/Test-DevFleet.ps1", ["Desktop"])
            ];
        throw new InvalidOperationException($"Unsupported DevFleet role: {role}");
    }
}

public sealed record InstallerExecutionReport(string Mode, string Role, IReadOnlyList<string> Stages, bool NetworkDownloadsAttempted, int ExitCode, string Detail);

public sealed class InstallService
{
    // Compatibility name retained for existing diagnostics; the effective
    // connected transaction deadline is role-aware and composed by
    // DeadlinePolicy.GetConnectedTransactionBudgetSeconds.
    public static readonly int ConnectedInstallTimeoutSeconds = DeadlinePolicy.DesktopTransactionSeconds;
    private readonly IProcessRunner _runner;
    private readonly bool _usesDefaultRunner;
    public InstallService(IProcessRunner? runner = null)
    {
        _usesDefaultRunner = runner is null;
        _runner = runner ?? new ProcessRunner(DeadlinePolicy.DesktopTransactionSeconds, allowEnvironmentOverride: false);
    }

    public InstallerExecutionReport Run(string releaseRoot, string role, string mode, Action<string>? progress = null, bool deferNetworkPairing = false, bool acknowledgeRootfulDocker = false)
    {
        var stages = InstallerStageCatalog.ForRole(role);
        foreach (var stage in stages) progress?.Invoke($"Stage planned: {stage.Name} ({stage.Script})");
        var script = Path.Combine(releaseRoot, "Install-DevFleet.ps1");
        if (!File.Exists(script)) throw new FileNotFoundException("The real DevFleet installation entry point is missing.", script);
        var normalizedRole = role.Contains("Laptop", StringComparison.OrdinalIgnoreCase) ? "Laptop" : "Desktop";
        var transactionBudgetSeconds = DeadlinePolicy.GetConnectedTransactionBudgetSeconds(normalizedRole);
        var transactionDeadlineUtc = DateTime.UtcNow.AddSeconds(transactionBudgetSeconds);
        var bootstrap = Path.Combine(releaseRoot, "Bootstrap-Install.ps1");
        var entry = File.Exists(bootstrap) ? bootstrap : script;
        var args = new List<string> { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", entry, "-Role", normalizedRole, "-NonInteractive", "-PackageRoot", releaseRoot, "-InstallationMode", "Connected", "-SkipWindowsUpdates", "-TransactionDeadlineUtc", transactionDeadlineUtc.ToString("O"), "-DeadlinePolicyVersion", DeadlinePolicy.Version };
        if (deferNetworkPairing) args.Add("-DeferNetworkPairing");
        if (acknowledgeRootfulDocker) args.Add("-AcknowledgeRootfulDocker");
        progress?.Invoke($"Invoking actual connected installation chain: {Path.GetFileName(entry)} -Role {normalizedRole} -NonInteractive -InstallationMode Connected{(deferNetworkPairing ? " -DeferNetworkPairing" : "")}");
        var runner = _usesDefaultRunner ? new ProcessRunner(transactionBudgetSeconds, allowEnvironmentOverride: false) : _runner;
        var result = runner.Run(FindPowerShell(entry), args, releaseRoot);
        if (result.ExitCode == 3010)
            return new InstallerExecutionReport(mode, normalizedRole, Array.Empty<string>(), true, result.ExitCode, "The verified installer entry point persisted a reboot checkpoint." + (result.OutputComplete ? "" : " Redirected output was incomplete after the bounded post-exit drain."));
        if (result.ExitCode != 0) throw new InvalidOperationException($"DevFleet installation chain failed ({result.ExitCode}): {result.StandardError}{(result.OutputComplete ? "" : " [redirected output incomplete after bounded post-exit drain]")}");
        foreach (var stage in stages) progress?.Invoke($"Stage verified by entry-point completion: {stage.Name}");
        return new InstallerExecutionReport(mode, normalizedRole, stages.Select(s => s.Name).ToArray(), true, result.ExitCode, result.OutputComplete ? result.StandardOutput.Trim() : "Installer entry point exited 0; redirected output was incomplete after the bounded post-exit drain.");
    }

    private static string FindPowerShell(string entry) => TrustedExecutableResolver.PowerShellPath();
}

internal static class TrustedExecutableResolver
{
    public static string PowerShellPath()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var pwsh = Path.Combine(programFiles, "PowerShell", "7", "pwsh.exe");
        if (File.Exists(pwsh)) return pwsh;
        var systemPowerShell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
        if (File.Exists(systemPowerShell)) return systemPowerShell;
        throw new FileNotFoundException("No trusted machine PowerShell executable was found.");
    }

    public static string SystemExecutable(string name)
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), name);
        if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0) return path;
        throw new FileNotFoundException($"No trusted system executable was found: {name}", path);
    }

    public static string VsCodePath()
    {
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Microsoft VS Code", "Code.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Microsoft VS Code", "Code.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Microsoft VS Code", "Code.exe")
        };
        foreach (var candidate in candidates)
        {
            if (!File.Exists(candidate) || (File.GetAttributes(candidate) & FileAttributes.ReparsePoint) != 0) continue;
            var full = Path.GetFullPath(candidate);
            if (full.EndsWith(Path.Combine("Microsoft VS Code", "Code.exe"), StringComparison.OrdinalIgnoreCase)) return full;
        }
        throw new FileNotFoundException("A trusted Microsoft VS Code installation was not found in an expected install root.");
    }
}

public sealed class RepairService
{
    private readonly InstallService _install;
    public RepairService(InstallService? install = null) => _install = install ?? new InstallService();
    public InstallerExecutionReport Repair(string releaseRoot, string role, Action<string>? progress = null, bool deferNetworkPairing = false, bool acknowledgeRootfulDocker = false) => _install.Run(releaseRoot, role, "Repair", progress, deferNetworkPairing, acknowledgeRootfulDocker);
}

public sealed class CleanReinstallService
{
    public void PreserveAndReconcile(IReadOnlyList<DiscoveredProject> projects, Action<string>? progress = null)
    {
        progress?.Invoke($"Clean Reinstall preservation plan verified for {projects.Count} discovered project(s); project VMs and backups remain outside the control-plane removal scope.");
    }
}

public sealed class UninstallService
{
    public void RemoveOwnedControlPlane(IReadOnlyList<string> files, IReadOnlyList<string> shortcuts, Action<string>? progress = null)
    {
        foreach (var file in files.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (File.Exists(file)) File.Delete(file);
            if (File.Exists(file)) throw new IOException($"Owned file remains after uninstall cleanup: {file}");
            progress?.Invoke($"Uninstall verified owned file absent: {file}");
        }
        foreach (var shortcut in shortcuts.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (File.Exists(shortcut)) File.Delete(shortcut);
            if (File.Exists(shortcut)) throw new IOException($"Owned shortcut remains after uninstall cleanup: {shortcut}");
            progress?.Invoke($"Uninstall verified owned shortcut absent: {shortcut}");
        }
    }
}

public static class CleanupJournalService
{
    private sealed class Journal
    {
        public int SchemaVersion { get; set; } = 1;
        public string TransactionId { get; set; } = "";
        public string Mode { get; set; } = "";
        public string InstallationGeneration { get; set; } = "";
        public string PayloadFingerprint { get; set; } = "";
        public List<string> CompletedStages { get; set; } = [];
        public string State { get; set; } = "in-progress";
        public string? LastError { get; set; }
        public string UpdatedUtc { get; set; } = "";
    }

    private static string PathFor(string mode) => Path.Combine(AppPaths.StateRoot, $"{mode.ToLowerInvariant()}-cleanup-journal.json");
    private static Journal ReadOrCreate(string mode, string transactionId, string installationGeneration, string payloadFingerprint)
    {
        var path = PathFor(mode);
        if (File.Exists(path))
        {
            var existing = JsonSerializer.Deserialize<Journal>(File.ReadAllText(path));
            if (existing is not null && existing.Mode.Equals(mode, StringComparison.OrdinalIgnoreCase) && existing.TransactionId == transactionId && existing.InstallationGeneration == installationGeneration && existing.PayloadFingerprint == payloadFingerprint) return existing;
        }
        return new Journal { TransactionId = transactionId, Mode = mode, InstallationGeneration = installationGeneration, PayloadFingerprint = payloadFingerprint, UpdatedUtc = DateTime.UtcNow.ToString("O") };
    }

    private static void Save(string mode, Journal journal)
    {
        Directory.CreateDirectory(AppPaths.StateRoot);
        journal.UpdatedUtc = DateTime.UtcNow.ToString("O");
        var path = PathFor(mode); var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(journal, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temp, path, true);
    }

    public static void Execute(string mode, string transactionId, IReadOnlyList<(string Name, Action Action)> stages, Action<string>? progress = null, string installationGeneration = "", string payloadFingerprint = "")
    {
        var journal = ReadOrCreate(mode, transactionId, installationGeneration, payloadFingerprint); Save(mode, journal);
        foreach (var stage in stages)
        {
            if (journal.CompletedStages.Contains(stage.Name, StringComparer.OrdinalIgnoreCase)) continue;
            try
            {
                stage.Action();
                journal.CompletedStages.Add(stage.Name); journal.LastError = null; Save(mode, journal);
                progress?.Invoke($"Cleanup stage completed: {stage.Name}");
            }
            catch (Exception ex)
            {
                journal.State = "incomplete"; journal.LastError = ex.Message; Save(mode, journal);
                throw;
            }
        }
        journal.State = "completed"; journal.LastError = null; Save(mode, journal);
        var activePath = PathFor(mode); var historyRoot = Path.Combine(AppPaths.StateRoot, "cleanup-history"); Directory.CreateDirectory(historyRoot);
        File.Move(activePath, Path.Combine(historyRoot, $"{mode.ToLowerInvariant()}-{transactionId}.json"), true);
    }
}

public sealed class FactoryResetService
{
    private readonly VmOwnershipService _vms;
    public FactoryResetService(BackupVerificationService _, VmOwnershipService vms) { _vms = vms; }
    public void DeleteSelected(DiscoveredProject project, Action<string>? progress = null)
    {
        // Historical backups are restore points only.  Destructive authorization
        // must use a new backup made for this exact reset transaction.
        var backup = _vms.CreateFreshSafetyBackup(project, progress);
        if (!backup.IsVerified) throw new InvalidOperationException($"Factory Reset blocked for {project.Slug}: fresh safety backup verification failed.");
        _vms.DeleteOwnedExact(project.ProjectId, project.RuntimeId, backup, progress);
    }
}

public sealed class DependencyService
{
    private readonly IProcessRunner _runner;
    private readonly HttpClient _http;
    private readonly Dictionary<string, string> _verifiedVendorDigests = new(StringComparer.OrdinalIgnoreCase);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { PropertyNameCaseInsensitive = true };
    public DependencyService(IProcessRunner? runner = null, HttpClient? http = null) { _runner = runner ?? new ProcessRunner(); _http = http ?? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromMinutes(5) }; }
    public static IReadOnlyList<DependencyDefinition> Catalog { get; } = LoadCatalog();

    private static IReadOnlyList<DependencyDefinition> LoadCatalog()
    {
#if DEBUG
        var path = Environment.GetEnvironmentVariable("DEVFLEET_SETUP_DEPENDENCY_MANIFEST");
        if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
            return ReadManifest(File.ReadAllText(path));
#endif
        var release = Path.Combine(AppPaths.InstallRoot, "Release", PayloadManifest.DevFleetVersion, "dependencies.json");
        if (File.Exists(release)) return ReadManifest(File.ReadAllText(release));
        var assembly = typeof(DependencyService).Assembly;
        var resource = assembly.GetManifestResourceNames().FirstOrDefault(x => x.EndsWith("dependencies.json", StringComparison.OrdinalIgnoreCase));
        if (resource is not null)
        {
            using var stream = assembly.GetManifestResourceStream(resource);
            using var reader = new StreamReader(stream ?? throw new InvalidDataException("Dependency manifest resource is unavailable."));
            return ReadManifest(reader.ReadToEnd());
        }
        throw new InvalidDataException("Canonical dependencies.json was not embedded or staged.");
    }

    private static IReadOnlyList<DependencyDefinition> ReadManifest(string json)
    {
        var manifest = JsonSerializer.Deserialize<DependencyManifestDocument>(json, JsonOptions)
            ?? throw new InvalidDataException("Canonical dependency manifest is empty.");
        if (manifest.SchemaVersion != 1 || manifest.ManifestVersion != PayloadManifest.DevFleetVersion || manifest.Dependencies.Count == 0)
            throw new InvalidDataException("Canonical dependency manifest version or schema is invalid.");
        return manifest.Dependencies;
    }

    public DependencyDetection Detect(DependencyDefinition dependency)
    {
        DependencyDetection? firstObserved = null;
        foreach (var candidate in CandidatePaths(dependency).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!File.Exists(candidate)) continue;
            if (!IsTrustedInstalledDependency(candidate, dependency)) continue;
            var version = ReadVersion(candidate, dependency);
            var compatible = version is not null && version >= dependency.MinimumVersion && (!dependency.MaximumMajor.HasValue || version.Major <= dependency.MaximumMajor.Value);
            var observed = new DependencyDetection(dependency.Name, true, Path.GetFullPath(candidate), version, compatible, "trusted machine PATH/HKLM/known-path discovery", dependency.Classification);
            firstObserved ??= observed;
            if (compatible) return observed;
        }
        return firstObserved ?? new(dependency.Name, false, "", null, false, "not detected or no trusted candidate", dependency.Classification);
    }

    public DependencyDetection ResolveCompatibleVersion(DependencyDefinition dependency) => Detect(dependency);

    public WingetHealth GetWingetHealth()
    {
        var wingetPolicy = new DependencyDefinition { DisplayName = "WinGet", InstallerAuthenticityPolicy = new InstallerAuthenticityPolicy { Required = true, AllowedSignerSubjectsExact = ["CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"] } };
        var winget = LocateOnPath("winget.exe", wingetPolicy);
        if (winget is null) return new("Missing", "", "", "winget.exe was not found on PATH.");
        var info = _runner.Run(winget, ["--version"]);
        if (info.ExitCode != 0) return new("Broken", winget, "", "winget --version failed: " + info.StandardError.Trim());
        if (!info.OutputComplete) return new("Broken", winget, "", "winget --version output was incomplete after the bounded post-exit drain.");
        var version = ExtractVersion(info.StandardOutput + " " + info.StandardError)?.ToString() ?? "Unknown";
        var sources = _runner.Run(winget, ["source", "list", "--disable-interactivity"]);
        if (sources.ExitCode != 0) return new("SourceBroken", winget, version, "winget source list failed: " + sources.StandardError.Trim());
        if (!sources.OutputComplete) return new("SourceBroken", winget, version, "winget source list output was incomplete after the bounded post-exit drain.");
        var search = _runner.Run(winget, ["search", "--id", "Microsoft.PowerShell", "--exact", "--source", "winget", "--disable-interactivity"]);
        if (search.ExitCode != 0) return new("SourceBroken", winget, version, "winget search failed: " + search.StandardError.Trim());
        if (!search.OutputComplete) return new("SourceBroken", winget, version, "winget search output was incomplete after the bounded post-exit drain.");
        return new("Healthy", winget, version, "version, source list and package search succeeded.");
    }

    public ProcessResult RepairWinget()
    {
        var command = "Install-PackageProvider -Name NuGet -Force | Out-Null; Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery | Out-Null; Repair-WinGetPackageManager -Force -Latest";
        return _runner.Run(TrustedExecutableResolver.PowerShellPath(), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command]);
    }

    public string DownloadOfficial(DependencyDefinition dependency, string destinationRoot)
    {
        Directory.CreateDirectory(destinationRoot);
        var winget = GetWingetHealth();
        if (winget.Status == "Healthy" && !string.IsNullOrWhiteSpace(dependency.WingetPackageId))
        {
            var result = _runner.Run(winget.ExecutablePath, ["download", "--id", dependency.WingetPackageId!, "--exact", "--source", "winget", "--accept-source-agreements", "--accept-package-agreements", "--download-directory", destinationRoot]);
            if (result.ExitCode == 0)
            {
                var package = Directory.EnumerateFiles(destinationRoot, "*", SearchOption.AllDirectories).OrderByDescending(File.GetLastWriteTimeUtc).FirstOrDefault();
                if (package is not null) return package;
            }
        }
        return DownloadDirectOfficial(dependency, destinationRoot);
    }

    private string DownloadDirectOfficial(DependencyDefinition dependency, string destinationRoot)
    {
        if (dependency.DirectOfficialVendorResolver.Type.Equals("windows-capability", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"{dependency.Name} requires the supported Windows capability path; no executable vendor payload is applicable.");
        var metadataUri = dependency.OfficialMetadata;
        if (!dependency.DirectOfficialVendorResolver.AllowedHosts.Contains(metadataUri.Host, StringComparer.OrdinalIgnoreCase))
            throw new InvalidDataException($"Official metadata host is not allowlisted for {dependency.Name}: {metadataUri.Host}");
        using var response = GetAllowlistedResponse(metadataUri, dependency.DirectOfficialVendorResolver.AllowedHosts, dependency.Name);
        response.EnsureSuccessStatusCode();
        var pattern = dependency.DirectOfficialVendorResolver.AssetRegex ?? throw new InvalidDataException($"No official asset rule for {dependency.Name}.");
        string assetName;
        Uri url;
        string? expectedDigest = null;
        if (dependency.DirectOfficialVendorResolver.Type.Equals("github-release", StringComparison.OrdinalIgnoreCase))
        {
            using var json = JsonDocument.Parse(response.Content.ReadAsStream());
            var root = json.RootElement;
            var tag = root.GetProperty("tag_name").GetString() ?? throw new InvalidDataException($"Official release tag is missing for {dependency.Name}.");
            if (!string.IsNullOrWhiteSpace(dependency.DirectOfficialVendorResolver.ExpectedOwner) && root.GetProperty("author").GetProperty("login").GetString() != dependency.DirectOfficialVendorResolver.ExpectedOwner)
                throw new InvalidDataException($"Official release owner mismatch for {dependency.Name}.");
            if (!string.IsNullOrWhiteSpace(dependency.DirectOfficialVendorResolver.ExpectedRepository) && !(root.GetProperty("html_url").GetString() ?? "").Contains($"/{dependency.DirectOfficialVendorResolver.ExpectedOwner}/{dependency.DirectOfficialVendorResolver.ExpectedRepository}/releases/", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"Official release repository mismatch for {dependency.Name}.");
            string? pageAssetName = null;
            if (!string.IsNullOrWhiteSpace(dependency.DirectOfficialVendorResolver.OfficialPageUri))
            {
                using var pageResponse = GetAllowlistedResponse(new Uri(dependency.DirectOfficialVendorResolver.OfficialPageUri), dependency.DirectOfficialVendorResolver.AllowedHosts, dependency.Name);
                var page = pageResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                var pagePattern = dependency.DirectOfficialVendorResolver.OfficialPageAssetRegex ?? pattern;
                foreach (Match match in Regex.Matches(page, "href\\s*=\\s*['\"](?<href>[^'\"]+)['\"]", RegexOptions.IgnoreCase))
                {
                    var href = match.Groups["href"].Value;
                    if (Uri.TryCreate(href, UriKind.Absolute, out var pageUri) && Regex.IsMatch(Path.GetFileName(pageUri.AbsolutePath), pagePattern) && pageUri.AbsolutePath.Contains($"/releases/download/{tag}/", StringComparison.OrdinalIgnoreCase))
                    {
                        pageAssetName = Path.GetFileName(pageUri.AbsolutePath);
                        break;
                    }
                }
                if (pageAssetName is null) throw new InvalidDataException($"Official download page did not identify a release asset matching tag {tag} for {dependency.Name}.");
            }
            var assets = root.GetProperty("assets").EnumerateArray().Where(x => Regex.IsMatch(x.GetProperty("name").GetString() ?? "", pattern) && (pageAssetName is null || x.GetProperty("name").GetString() == pageAssetName)).ToArray();
            if (assets.Length != 1) throw new InvalidDataException($"Expected exactly one official x64 asset for {dependency.Name}, found {assets.Length}.");
            var asset = assets[0];
            assetName = asset.GetProperty("name").GetString()!;
            url = new Uri(asset.GetProperty("browser_download_url").GetString() ?? "");
            if (!url.AbsolutePath.Contains($"/{dependency.DirectOfficialVendorResolver.ExpectedOwner}/{dependency.DirectOfficialVendorResolver.ExpectedRepository}/releases/download/{tag}/", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException($"Official release asset path/tag mismatch for {dependency.Name}.");
            if (asset.TryGetProperty("digest", out var digestElement)) expectedDigest = digestElement.GetString();
        }
        else if (dependency.DirectOfficialVendorResolver.Type.Equals("official-download-page", StringComparison.OrdinalIgnoreCase))
        {
            if (!string.IsNullOrWhiteSpace(dependency.DirectOfficialVendorResolver.DirectUri))
            {
                var directUri = new Uri(dependency.DirectOfficialVendorResolver.DirectUri);
                if (!dependency.DirectOfficialVendorResolver.AllowedHosts.Contains(directUri.Host, StringComparer.OrdinalIgnoreCase)) throw new InvalidDataException($"Official direct URI host is not allowlisted for {dependency.Name}: {directUri.Host}");
                using var directResponse = GetAllowlistedResponse(directUri, dependency.DirectOfficialVendorResolver.AllowedHosts, dependency.Name);
                url = directResponse.RequestMessage?.RequestUri ?? directUri;
                assetName = Path.GetFileName(url.AbsolutePath);
                if (string.IsNullOrWhiteSpace(assetName) || !Regex.IsMatch(assetName, pattern)) throw new InvalidDataException($"Official direct URI resolved to an unexpected asset for {dependency.Name}: {assetName}");
            }
            else
            {
                var html = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                var links = Regex.Matches(html, @"href\s*=\s*[""'](?<href>[^""']+)[""']", RegexOptions.IgnoreCase).Select(x => x.Groups["href"].Value);
                var selected = links.Select(x => Uri.TryCreate(metadataUri, x, out var candidate) ? candidate : null).Where(x => x is not null && dependency.DirectOfficialVendorResolver.AllowedHosts.Contains(x.Host, StringComparer.OrdinalIgnoreCase) && Regex.IsMatch(Path.GetFileName(x.AbsolutePath), pattern)).FirstOrDefault();
                if (selected is null) throw new InvalidDataException($"No allowlisted official download-page asset matched for {dependency.Name}.");
                url = selected;
                assetName = Path.GetFileName(url.AbsolutePath);
            }
        }
        else throw new InvalidOperationException($"Direct official resolver is not implemented for {dependency.Name}; refusing an unauthenticated fallback. Metadata: {dependency.OfficialMetadata}");
        if (!dependency.DirectOfficialVendorResolver.AllowedHosts.Contains(url.Host, StringComparer.OrdinalIgnoreCase)) throw new InvalidDataException($"Official asset host is not allowlisted for {dependency.Name}: {url.Host}");
        var path = Path.Combine(destinationRoot, assetName);
        Exception? last = null;
        for (var attempt = 1; attempt <= 3; attempt++)
        {
            try
            {
                using var downloadResponse = GetAllowlistedResponse(url, dependency.DirectOfficialVendorResolver.AllowedHosts, dependency.Name);
                using var download = downloadResponse.Content.ReadAsStream();
                using var output = File.Create(path);
                download.CopyTo(output);
                if (dependency.InstallerAuthenticityPolicy.Strategy is "VendorReleaseSha256" or "AuthenticodeOrVendorReleaseSha256")
                {
                    if (string.IsNullOrWhiteSpace(expectedDigest)) throw new InvalidDataException($"Official vendor release did not provide a SHA-256 digest for {dependency.Name}.");
                    _verifiedVendorDigests[path] = VendorReleaseAuthenticity.NormalizeDigest(expectedDigest);
                    VendorReleaseAuthenticity.VerifySha256(path, expectedDigest);
                }
                return path;
            }
            catch (Exception ex) when (attempt < 3) { last = ex; Thread.Sleep(TimeSpan.FromSeconds(attempt)); }
        }
        throw new IOException($"Official download failed after bounded retries for {dependency.Name}.", last);
    }

    public void VerifyInstaller(string installerPath, DependencyDefinition? dependency = null)
    {
        if (!File.Exists(installerPath)) throw new FileNotFoundException("Dependency installer is missing.", installerPath);
        if (dependency?.InstallerAuthenticityPolicy.Strategy is "VendorReleaseSha256" or "AuthenticodeOrVendorReleaseSha256")
        {
            if (!_verifiedVendorDigests.TryGetValue(installerPath, out var digest)) throw new InvalidDataException($"No verified official vendor digest is bound to {Path.GetFileName(installerPath)}.");
            VendorReleaseAuthenticity.VerifySha256(installerPath, digest);
            return;
        }
        var escaped = installerPath.Replace("'", "''");
        var result = _runner.Run(TrustedExecutableResolver.PowerShellPath(), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", $"$s=Get-AuthenticodeSignature -LiteralPath '{escaped}'; if($s.Status -ne 'Valid'){{exit 9}}; $s.SignerCertificate.Subject"]);
        if (result.ExitCode != 0 || !result.OutputComplete || string.IsNullOrWhiteSpace(result.StandardOutput)) throw new InvalidDataException($"Authenticode verification failed for {Path.GetFileName(installerPath)}{(result.OutputComplete ? "." : ": redirected signer output was incomplete.")}");
        if (dependency is not null && dependency.InstallerAuthenticityPolicy.AllowedSignerSubjectsExact.Length > 0)
        {
            var subject = result.StandardOutput.Trim();
            if (!SignerIdentity.MatchesExact(subject, dependency.InstallerAuthenticityPolicy.AllowedSignerSubjectsExact))
                throw new InvalidDataException($"Authenticode signer is not allowlisted for {dependency.Name}: {subject}");
        }
        else if (dependency is not null && dependency.InstallerAuthenticityPolicy.AllowedSignerPatterns.Length > 0)
            throw new InvalidDataException($"Legacy substring signer policy is rejected for {dependency.Name}; release policy must provide AllowedSignerSubjectsExact.");
    }

    private HttpResponseMessage GetAllowlistedResponse(Uri initialUri, IReadOnlyCollection<string> allowedHosts, string dependencyName)
    {
        var uri = initialUri;
        for (var hop = 0; hop <= 5; hop++)
        {
            if (!uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(uri.Host) || !string.IsNullOrEmpty(uri.UserInfo))
                throw new InvalidDataException($"Official download redirect is not an allowlisted HTTPS URI for {dependencyName}: {uri}");
            if (!allowedHosts.Contains(uri.Host, StringComparer.OrdinalIgnoreCase))
                throw new InvalidDataException($"Official download host is not allowlisted for {dependencyName}: {uri.Host}");
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.UserAgent.ParseAdd($"DevFleet-Setup/{PayloadManifest.InstallerVersion}");
            var response = _http.Send(request);
            if ((int)response.StatusCode is >= 300 and <= 399)
            {
                var location = response.Headers.Location;
                response.Dispose();
                if (location is null) throw new InvalidDataException($"Official download redirect omitted Location for {dependencyName}.");
                uri = new Uri(uri, location);
                continue;
            }
            response.EnsureSuccessStatusCode();
            return response;
        }
        throw new InvalidDataException($"Official download exceeded the redirect limit for {dependencyName}.");
    }

    public DependencyResult Install(DependencyDefinition dependency, string installerPath)
    {
        VerifyInstaller(installerPath, dependency);
        var args = dependency.SilentInstallArguments.Length == 0 ? ["/quiet", "/norestart"] : dependency.SilentInstallArguments;
        ProcessResult result = Path.GetExtension(installerPath).Equals(".msi", StringComparison.OrdinalIgnoreCase)
            ? _runner.Run(TrustedExecutableResolver.SystemExecutable("msiexec.exe"), ["/i", installerPath, .. args])
            : _runner.Run(installerPath, args);
        if (result.ExitCode is not (0 or 3010)) throw new InvalidOperationException($"{dependency.Name} installation failed ({result.ExitCode}): {result.StandardError}");
        var detected = Detect(dependency);
        if (!detected.Compatible) throw new InvalidOperationException($"{dependency.Name} completed but a compatible executable was not discovered.");
        return new(true, true, result.ExitCode == 3010, $"{dependency.Name} {detected.Version} at {detected.ExecutablePath}");
    }

    public IReadOnlyList<DependencyDetection> DetectAll() => Catalog.Select(Detect).ToArray();
    public DependencyResult VerifyLocalPayload(string dependencyRoot)
    {
        if (!Directory.Exists(dependencyRoot)) return new(false, false, false, "Offline prerequisite payload directory is absent.");
        var manifestPath = Path.Combine(dependencyRoot, "OFFLINE-DEPENDENCIES.json");
        if (!File.Exists(manifestPath)) return new(false, false, false, "Release-bound offline dependency manifest is absent.");
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(manifestPath));
            var root = document.RootElement;
            if (root.GetProperty("schemaVersion").GetInt32() != 2 || root.GetProperty("devfleetVersion").GetString() != PayloadManifest.DevFleetVersion || !root.TryGetProperty("releaseBinding", out _))
                return new(false, false, false, "Offline dependency manifest is not bound to this release.");
            if (!root.TryGetProperty("payloads", out var payloads) || payloads.ValueKind != JsonValueKind.Array)
                return new(false, false, false, "Release-bound offline payload entries are absent.");
            var entries = payloads.EnumerateArray().ToArray();
            var entryByName = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in entries)
            {
                var fileName = entry.GetProperty("filename").GetString() ?? "";
                var dependencyId = entry.GetProperty("dependencyId").GetString() ?? "";
                var expectedSha = entry.GetProperty("sha256").GetString() ?? "";
                var expectedSize = entry.GetProperty("sizeBytes").GetInt64();
                if (string.IsNullOrWhiteSpace(dependencyId) || string.IsNullOrWhiteSpace(fileName) || Path.IsPathRooted(fileName) || fileName.Contains("..", StringComparison.Ordinal) || !Regex.IsMatch(expectedSha, "^[0-9a-fA-F]{64}$") || expectedSize < 0 || !entryByName.TryAdd(fileName, entry))
                    return new(false, false, false, "Offline payload manifest contains an invalid or duplicate entry.");
            }
            var files = Directory.EnumerateFiles(dependencyRoot, "*", SearchOption.AllDirectories)
                .Where(path => !path.Equals(manifestPath, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            var actualByName = files.ToDictionary(path => Path.GetRelativePath(dependencyRoot, path), StringComparer.OrdinalIgnoreCase);
            if (actualByName.Keys.Any(name => !entryByName.ContainsKey(name)) || entryByName.Keys.Any(name => !actualByName.ContainsKey(name)))
                return new(false, false, false, "Offline payload files must match the release-bound manifest exactly.");
            foreach (var (fileName, entry) in entryByName)
            {
                var path = actualByName[fileName];
                var expectedSize = entry.GetProperty("sizeBytes").GetInt64();
                var expectedSha = entry.GetProperty("sha256").GetString()!.ToLowerInvariant();
                if (new FileInfo(path).Length != expectedSize) return new(false, false, false, $"Offline payload size mismatch: {fileName}.");
                using var stream = File.OpenRead(path);
                var actualSha = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
                if (!actualSha.Equals(expectedSha, StringComparison.OrdinalIgnoreCase)) return new(false, false, false, $"Offline payload SHA-256 mismatch: {fileName}.");
                if (!entry.TryGetProperty("signerPolicy", out var signerPolicy) || signerPolicy.ValueKind != JsonValueKind.Object)
                    return new(false, false, false, $"Offline payload signer policy is missing: {fileName}.");
            }
            return new(files.Length > 0, false, false, files.Length > 0 ? $"Verified {files.Length} exact release-bound local dependency payload file(s); no installer was executed." : "No release-bound offline dependency payloads are included.");
        }
        catch (Exception ex) { return new(false, false, false, $"Offline dependency manifest is invalid: {ex.Message}"); }
    }

    private IEnumerable<string> CandidatePaths(DependencyDefinition dependency)
    {
        foreach (var executable in dependency.ExecutableProbes)
        {
            foreach (var command in LocateOnPathAll(executable)) yield return command;
            foreach (var hive in new[] { Registry.LocalMachine })
            foreach (var view in new[] { $@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{executable}", $@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\{executable}" })
            {
                using var key = hive.OpenSubKey(view); var value = key?.GetValue(null)?.ToString(); if (!string.IsNullOrWhiteSpace(value)) yield return value.Trim('"');
            }
        }
        foreach (var known in dependency.KnownVendorInstallLocations.Select(Environment.ExpandEnvironmentVariables)) yield return known;
    }

    private bool IsTrustedInstalledDependency(string executable, DependencyDefinition dependency)
    {
        var full = Path.GetFullPath(executable);
        if (Path.GetExtension(full).Equals(".cmd", StringComparison.OrdinalIgnoreCase) || Path.GetExtension(full).Equals(".bat", StringComparison.OrdinalIgnoreCase)) return false;
        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) return false;
        string systemRoot;
        if (Path.GetFileName(full).Equals("winget.exe", StringComparison.OrdinalIgnoreCase))
        {
            // WinGet is trusted only beneath the exact physical AppX package
            // root returned by the identity probe, never merely because it is
            // somewhere below Program Files or a local WindowsApps alias.
            if (!TryGetTrustedWinGetPackageRoot(full, out systemRoot)) return false;
        }
        else if (!OwnedPathSafety.TryGetTrustedSystemRoot(full, out systemRoot)) return false;
        var trustedRoot = systemRoot;
        try
        {
            var cursor = new DirectoryInfo(Path.GetDirectoryName(full)!);
            var root = new DirectoryInfo(trustedRoot);
            if (!root.Exists || root.Attributes.HasFlag(FileAttributes.ReparsePoint)) return false;
            var reachedRoot = false;
            while (cursor is not null)
            {
                if ((cursor.Attributes & FileAttributes.ReparsePoint) != 0) return false;
                if (OperatingSystem.IsWindows())
                {
                    var acl = cursor.GetAccessControl();
                    foreach (var rule in acl.GetAccessRules(true, true, typeof(NTAccount)).OfType<FileSystemAccessRule>())
                    {
                        if (OwnedPathSafety.IsBroadUntrustedPrincipal(rule.IdentityReference.Value) && rule.AccessControlType == AccessControlType.Allow && OwnedPathSafety.HasPrimitiveMutationRights(rule.FileSystemRights)) return false;
                    }
                }
                if (cursor.FullName.TrimEnd(Path.DirectorySeparatorChar).Equals(root.FullName.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
                {
                    reachedRoot = true;
                    break;
                }
                cursor = cursor.Parent;
            }
            if (!reachedRoot) return false;
        }
        catch { return false; }
        var signer = ReadAuthenticodeSubject(full);
        var allowUnsignedInstalled = string.IsNullOrWhiteSpace(signer)
            && dependency.InstallerAuthenticityPolicy.InstalledExecutableTrust.Equals("signed-installer-locked-path", StringComparison.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(signer)) return allowUnsignedInstalled;
        var exact = dependency.InstallerAuthenticityPolicy.AllowedSignerSubjectsExact;
        if (exact.Length > 0) return SignerIdentity.MatchesExact(signer, exact);
        return dependency.InstallerAuthenticityPolicy.AllowedSignerPatterns.Length == 0;
    }

    private string? ReadAuthenticodeSubject(string executable)
    {
        var escaped = executable.Replace("'", "''", StringComparison.Ordinal);
        var result = _runner.Run(TrustedExecutableResolver.PowerShellPath(), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "$s=Get-AuthenticodeSignature -LiteralPath '" + escaped + "'; if($s.Status -ne 'Valid'){exit 9}; $s.SignerCertificate.Subject"]);
        return result.ExitCode == 0 && result.OutputComplete ? result.StandardOutput.Trim() : null;
    }

    private bool TryGetTrustedWinGetPackageRoot(string executable, out string packageRoot)
    {
        packageRoot = "";
        // The only accepted AppX identity is Microsoft.DesktopAppInstaller /
        // 8wekyb3d8bbwe, with an exact physical x64 package-root basename.
        var machineWindowsApps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps");
        var command = "Get-AppxPackage -AllUsers -Name 'Microsoft.DesktopAppInstaller' | ForEach-Object { $_.Name + '|' + $_.PublisherId + '|' + $_.InstallLocation }";
        var result = _runner.Run(TrustedExecutableResolver.PowerShellPath(), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command]);
        if (result.ExitCode != 0 || !result.OutputComplete) return false;
        var matches = new List<string>();
        foreach (var line in result.StandardOutput.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var fields = line.Split('|', 3);
            if (fields.Length == 3 && OwnedPathSafety.IsExactWindowsAppxPackageCandidate(executable, fields[2].Trim(), machineWindowsApps, fields[0].Trim(), fields[1].Trim()))
            {
                matches.Add(Path.GetFullPath(fields[2].Trim()).TrimEnd(Path.DirectorySeparatorChar));
            }
        }
        if (matches.Distinct(StringComparer.OrdinalIgnoreCase).Count() != 1) return false;
        packageRoot = matches[0];
        return true;
    }

    private Version? ReadVersion(string executable, DependencyDefinition dependency)
    {
        if (dependency.Id == "virtualization-backend") return new Version(1, 0);
        var result = _runner.Run(executable, dependency.VersionProbe.Arguments);
        if (!result.OutputComplete) return null;
        var match = dependency.VersionProbe.Regex is null ? null : Regex.Match(result.StandardOutput + " " + result.StandardError, dependency.VersionProbe.Regex);
        return result.ExitCode == 0 && match is not null && match.Success && Version.TryParse(match.Groups[1].Value, out var version) ? version : null;
    }
    private static Version? ExtractVersion(string value) { var match = Regex.Match(value, @"(?<!\d)(\d+\.\d+(?:\.\d+){0,2})"); return match.Success && Version.TryParse(match.Groups[1].Value, out var v) ? v : null; }
    private static IEnumerable<string> LocateOnPathAll(string executable)
    {
        var path = Environment.GetEnvironmentVariable("PATH") ?? "";
        return path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries).Select(p => Path.Combine(p.Trim('"'), executable)).Where(File.Exists);
    }
    private string? LocateOnPath(string executable, DependencyDefinition dependency)
    {
        var candidates = LocateOnPathAll(executable).ToList();
        if (executable.Equals("winget.exe", StringComparison.OrdinalIgnoreCase))
        {
            var result = _runner.Run(TrustedExecutableResolver.PowerShellPath(), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Get-AppxPackage -AllUsers -Name 'Microsoft.DesktopAppInstaller' | ForEach-Object { Join-Path $_.InstallLocation 'winget.exe' }"]);
            if (result.ExitCode == 0 && result.OutputComplete) candidates.AddRange(result.StandardOutput.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries));
        }
        return candidates.Select(x => x.Trim()).Where(File.Exists).FirstOrDefault(path => IsTrustedInstalledDependency(path, dependency));
    }
}

public static class TailscaleAuthenticationService
{
    private static readonly Regex AuthUrl = new(@"https://login\.tailscale\.com/[A-Za-z0-9/_?=.&%-]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    public static Uri? ParseAuthenticationUri(string output)
    {
        var match = AuthUrl.Match(output ?? "");
        return match.Success && Uri.TryCreate(match.Value, UriKind.Absolute, out var uri) && uri.Host.Equals("login.tailscale.com", StringComparison.OrdinalIgnoreCase) ? uri : null;
    }
    public static TailscaleAuthentication Begin(IProcessRunner runner, string tailscalePath)
    {
        // Tailscale defaults to an unbounded wait when authentication is required.
        // Keep the UI responsive and expose the official URL after a bounded wait.
        var result = runner.Run(tailscalePath, ["up", "--timeout=30s"]);
        if (!result.OutputComplete) return new("Error", null, "Tailscale authentication output was incomplete; no authentication state or URL was accepted.");
        var uri = ParseAuthenticationUri(result.StandardOutput + Environment.NewLine + result.StandardError);
        if (uri is not null) return new("Authentication required", uri, "Open the official Tailscale authentication page after explicit user action.");
        if (result.ExitCode == 0) return new("Authenticated", null, "Tailscale reports an authenticated node.");
        return new("Error", null, $"Tailscale authentication command failed ({result.ExitCode}).");
    }
    public static async Task<TailscaleAuthentication> BeginAsync(IProcessRunner runner, string tailscalePath, CancellationToken cancellationToken = default)
    {
        var result = await runner.RunAsync(tailscalePath, ["up", "--timeout=30s"], cancellationToken: cancellationToken).ConfigureAwait(false);
        if (!result.OutputComplete) return new("Error", null, "Tailscale authentication output was incomplete; no authentication state or URL was accepted.");
        var uri = ParseAuthenticationUri(result.StandardOutput + Environment.NewLine + result.StandardError);
        if (uri is not null) return new("Authentication required", uri, "Open the official Tailscale authentication page after explicit user action.");
        if (result.ExitCode == 0) return new("Authenticated", null, "Tailscale reports an authenticated node.");
        return new("Error", null, $"Tailscale authentication command failed ({result.ExitCode}).");
    }
}

public sealed class RegistryService(IRegistryManager manager)
{
    public void RemoveExact(string key) => manager.RemoveExact(key);
}

public sealed class ShortcutService(IShortcutManager manager)
{
    public void RemoveExact(string path) => manager.RemoveExact(path);
}

public sealed class SshIntegrationService(ISshManager manager)
{
    public void RemoveManaged(string marker) => manager.RemoveManagedBlock(marker);
}

public sealed class VsCodeIntegrationService(IVsCodeManager manager)
{
    public void RemoveManaged(string alias) => manager.RemoveManagedAlias(alias);
}

public sealed class HostAgentService
{
    public bool IsPresent() => File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DevFleetHostAgent", "DevFleet-HostAgent.ps1"));
}

public sealed class WindowsOwnedIntegrationCleanupService
{
    private readonly IProcessRunner _runner;
    public WindowsOwnedIntegrationCleanupService(IProcessRunner? runner = null) => _runner = runner ?? new ProcessRunner();
    public void Cleanup(InstallLedger ledger, Action<string>? progress = null)
    {
        if (!OperatingSystem.IsWindows()) return;
        if (ledger.WindowsIntegrations.Count == 0 || string.IsNullOrWhiteSpace(ledger.WindowsIntegrationOwnershipPath) || string.IsNullOrWhiteSpace(ledger.InstallationGeneration)) throw new InvalidOperationException("Windows integration cleanup requires an exact installation ownership binding; same-name foreign resources were preserved. Use the explicit legacy adoption workflow first.");
        var helper = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DevFleetHostAgent", "Remove-DevFleet-OwnedIntegrations.ps1");
        if (!File.Exists(helper) || (File.GetAttributes(helper) & FileAttributes.ReparsePoint) != 0) throw new FileNotFoundException("Owned Windows integration cleanup helper is unavailable; resources were preserved.", helper);
        var result = _runner.Run(TrustedExecutableResolver.PowerShellPath(), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", helper, "-OwnershipPath", ledger.WindowsIntegrationOwnershipPath, "-ExpectedGeneration", ledger.InstallationGeneration]);
        if (result.ExitCode != 0) throw new InvalidOperationException($"Owned integration cleanup failed or remained incomplete. Owned scheduled task remains after cleanup, owned firewall rule remains after cleanup, or owned service remains after cleanup: {result.StandardError.Trim()}");
        progress?.Invoke("Removed only ledger-bound DevFleet Host Agent task/service/firewall identities after live binding verification.");
    }
}

public sealed class RebootRequiredException(string message) : Exception(message);

public sealed record DiscoveredProject(string ProjectId, string Slug, string Provider, string RuntimeId, string OwnerProof, string BackupManifest, bool RestoreEligible)
{
    public string VmName { get; init; } = "";
    public string HostId { get; init; } = "";
    public string LifecycleState { get; init; } = "unknown";
    public bool IsDevFleetOwned { get; init; }
    public string OwnershipSource { get; init; } = "unknown";
    public bool ProjectIdVerified { get; init; }
    public bool RuntimeIdVerified { get; init; }
    public string AmbiguityReason { get; init; } = "";
    public string OwnershipStatus => IsDevFleetOwned && ProjectIdVerified && RuntimeIdVerified && string.IsNullOrWhiteSpace(AmbiguityReason) ? "VERIFIED" : (string.IsNullOrWhiteSpace(AmbiguityReason) ? "UNVERIFIED" : "AMBIGUOUS");
}

public sealed class ProjectDiscoveryService
{
    public IReadOnlyList<DiscoveredProject> Discover()
    {
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        // An explicitly configured state root is the authoritative fixture/portable scope.
        // The normal production path remains Host Agent first when no override is present.
        var configuredStateRoot = TestEnvironment.IsTestProcess ? Environment.GetEnvironmentVariable("DEVFLEET_SETUP_STATE_ROOT") : null;
        var configured = new[] { Path.Combine(AppPaths.StateRoot, "projects.json"), Path.Combine(AppPaths.StateRoot, "HostAgent", "projects.json"), Path.Combine(AppPaths.StateRoot, "host-agent-registry.json") };
        var production = new[] { Path.Combine(programData, "DevFleetHostAgent", "projects.json"), Path.Combine(programData, "DevFleetHostAgent", "config.json"), Path.Combine(programData, "DevFleet", "projects.json") };
        var paths = string.IsNullOrWhiteSpace(configuredStateRoot) ? production.Concat(configured).ToArray() : configured.Concat(production).ToArray();
        foreach (var path in paths.Where(File.Exists))
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(path));
                var values = doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement.EnumerateArray().ToArray() : doc.RootElement.TryGetProperty("projects", out var projects) ? (projects.ValueKind == JsonValueKind.Object ? projects.EnumerateObject().Select(x => x.Value).ToArray() : projects.EnumerateArray().ToArray()) : [];
                var data = values.Select(Parse).Where(x => x is not null).Cast<DiscoveredProject>().ToArray();
                if (data.Length > 0) return data;
            }
            catch { }
        }
        return StateStore.ReadLedger().OwnedResources.Where(x => !string.IsNullOrWhiteSpace(x.ProjectId)).Select(x => new DiscoveredProject(x.ProjectId, x.Identity, x.Kind.Contains("Multipass", StringComparison.OrdinalIgnoreCase) ? "Multipass" : x.Kind, x.Path, x.OwnerProof, "", false)
        {
            IsDevFleetOwned = x.OwnerProof.Equals("DevFleetLedger", StringComparison.OrdinalIgnoreCase),
            OwnershipSource = "installation-ledger",
            ProjectIdVerified = !string.IsNullOrWhiteSpace(x.ProjectId),
            RuntimeIdVerified = !string.IsNullOrWhiteSpace(x.Path) && !x.Path.Contains('*'),
            AmbiguityReason = x.OwnerProof.Equals("DevFleetLedger", StringComparison.OrdinalIgnoreCase) ? "" : "Ledger ownership marker is not the canonical DevFleet marker."
        }).ToArray();
    }

    private static DiscoveredProject? Parse(JsonElement item)
    {
        if (!item.TryGetProperty("project_id", out var pid) || !item.TryGetProperty("slug", out var slug) || !item.TryGetProperty("runtime_id", out var runtime)) return null;
        var projectId = pid.GetString() ?? "";
        var projectSlug = slug.GetString() ?? "";
        var runtimeId = runtime.GetString() ?? "";
        var managedBy = item.TryGetProperty("managed_by", out var managed) ? managed.GetString() ?? "" : "";
        var hostId = item.TryGetProperty("host_id", out var hostElement) ? hostElement.GetString() ?? "" : "";
        var project = new DiscoveredProject(projectId, projectSlug, "Multipass Host Agent", runtimeId, managedBy, "", true)
        {
            VmName = item.TryGetProperty("vm_name", out var vm) ? vm.GetString() ?? "" : "",
            HostId = hostId,
            LifecycleState = item.TryGetProperty("state", out var state) ? state.GetString() ?? "unknown" : "unknown",
            IsDevFleetOwned = managedBy.Equals("devfleet", StringComparison.OrdinalIgnoreCase),
            OwnershipSource = "host-agent-registry",
            ProjectIdVerified = !string.IsNullOrWhiteSpace(projectId),
            RuntimeIdVerified = !string.IsNullOrWhiteSpace(runtimeId) && !runtimeId.Contains('*'),
            AmbiguityReason = managedBy.Equals("devfleet", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(hostId) ? "" : "Host Agent registry did not provide a complete canonical DevFleet ownership record."
        };
        var backup = item.TryGetProperty("backup_manifest", out var explicitManifest) ? explicitManifest.GetString() : null;
        foreach (var backupRoot in new[] { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DevFleetHostAgent", "backups"), Path.Combine(AppPaths.StateRoot, "backups") })
        {
            if (!string.IsNullOrWhiteSpace(backup) || !Directory.Exists(backupRoot)) continue;
            foreach (var candidate in Directory.EnumerateFiles(backupRoot, "*.json").OrderBy(Path.GetFileName, StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    using var backupDoc = JsonDocument.Parse(File.ReadAllText(candidate));
                    var root = backupDoc.RootElement;
                    var candidateProjectId = root.TryGetProperty("project_id", out var candidatePid) ? candidatePid.GetString() : null;
                    var rid = root.TryGetProperty("runtime_id", out var candidateRid) ? candidateRid.GetString() : null;
                    if (string.Equals(candidateProjectId, project.ProjectId, StringComparison.OrdinalIgnoreCase) && string.Equals(rid, project.RuntimeId, StringComparison.OrdinalIgnoreCase)) { backup = candidate; break; }
                }
                catch (JsonException) { }
            }
        }
        return project with { BackupManifest = backup ?? "" };
    }
}

public sealed record BackupReference(string Provider, string BackupId, string ProjectId, string Slug, string RuntimeId, string HostId, string ArchiveSha256, long ArchiveBytes, string ManifestSha256, string CreatedAt, string ConsistencyLevel);

public sealed record BackupVerification(string ProjectId, string BackupId, string ArchivePath, string ExpectedSha256, string ActualSha256, bool IdentityMatches, bool RestoreEligible, DateTime VerifiedUtc, BackupReference? Reference = null)
{
    public bool IsVerified => IdentityMatches && RestoreEligible && ExpectedSha256.Equals(ActualSha256, StringComparison.OrdinalIgnoreCase) && (Reference is not null ? Reference.ArchiveSha256.Equals(ActualSha256, StringComparison.OrdinalIgnoreCase) && Reference.ArchiveBytes >= 0 : File.Exists(ArchivePath));
}

public sealed class BackupVerificationService
{
    public BackupVerification Verify(DiscoveredProject project)
    {
        if (string.IsNullOrWhiteSpace(project.BackupManifest) || !File.Exists(project.BackupManifest)) return new(project.ProjectId, "", "", "", "", false, false, DateTime.UtcNow);
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(project.BackupManifest));
            var root = doc.RootElement;
            var projectId = root.TryGetProperty("project_id", out var pid) ? pid.GetString() ?? "" : root.TryGetProperty("projectId", out pid) ? pid.GetString() ?? "" : "";
            var archive = root.TryGetProperty("archive", out var ap) ? ap.GetString() ?? "" : root.TryGetProperty("archive_path", out ap) ? ap.GetString() ?? "" : root.TryGetProperty("archivePath", out ap) ? ap.GetString() ?? "" : "";
            var expected = root.TryGetProperty("sha256", out var sh) ? sh.GetString() ?? "" : root.TryGetProperty("archive_sha256", out sh) ? sh.GetString() ?? "" : "";
            var id = root.TryGetProperty("backup_id", out var bid) ? bid.GetString() ?? "" : root.TryGetProperty("backupId", out bid) ? bid.GetString() ?? "" : Path.GetFileNameWithoutExtension(archive);
            var actual = File.Exists(archive) ? Convert.ToHexString(ComputeSha256(archive)).ToLowerInvariant() : "";
            var slugMatches = !root.TryGetProperty("slug", out var sl) || string.Equals(sl.GetString(), project.Slug, StringComparison.OrdinalIgnoreCase);
            var runtimeMatches = !root.TryGetProperty("runtime_id", out var rt) || string.Equals(rt.GetString(), project.RuntimeId, StringComparison.OrdinalIgnoreCase);
            var hashesMatch = root.TryGetProperty("source_archive_sha256", out var source) && root.TryGetProperty("host_archive_sha256", out var host) && string.Equals(source.GetString(), host.GetString(), StringComparison.OrdinalIgnoreCase);
            return new(project.ProjectId, id, archive, expected, actual, projectId.Equals(project.ProjectId, StringComparison.OrdinalIgnoreCase) && slugMatches && runtimeMatches && hashesMatch, project.RestoreEligible, DateTime.UtcNow);
        }
        catch { return new(project.ProjectId, "", "", "", "", false, false, DateTime.UtcNow); }
    }

    private static byte[] ComputeSha256(string path)
    {
        using var stream = File.OpenRead(path);
        return SHA256.HashData(stream);
    }
}

public sealed record VmRecord(string Provider, string RuntimeId, string ProjectId, bool Owned, string Slug = "", string BackupId = "", string BackupSha256 = "");
public interface IVmProvider
{
    IReadOnlyList<VmRecord> Discover();
    BackupVerification CreateFreshBackup(VmRecord vm);
    void DeleteExact(VmRecord vm);
}

public sealed class RecordingVmProvider(IReadOnlyList<VmRecord> inventory) : IVmProvider
{
    public IReadOnlyList<VmRecord> Inventory { get; } = inventory;
    public List<string> DeletedRuntimeIds { get; } = [];
    public IReadOnlyList<VmRecord> Discover() => Inventory;
    public BackupVerification CreateFreshBackup(VmRecord vm) => throw new InvalidOperationException("Recording VM provider does not create destructive backups.");
    public void DeleteExact(VmRecord vm)
    {
        if (!vm.Owned) throw new InvalidOperationException("Refusing to delete an unproven VM.");
        if (vm.Provider.Equals("Multipass", StringComparison.OrdinalIgnoreCase) && vm.RuntimeId.Contains('*')) throw new InvalidOperationException("Wildcard VM deletion is forbidden.");
        DeletedRuntimeIds.Add(vm.RuntimeId);
    }
}

public sealed class MultipassHostAgentProvider : IVmProvider
{
    private readonly string _root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DevFleetHostAgent");
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(30) };

    public IReadOnlyList<VmRecord> Discover()
    {
        var registry = Path.Combine(_root, "projects.json");
        if (!File.Exists(registry)) return [];
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(registry));
            var projects = doc.RootElement.TryGetProperty("projects", out var p) ? p : doc.RootElement;
            var result = new List<VmRecord>();
            foreach (var item in projects.ValueKind == JsonValueKind.Object ? projects.EnumerateObject().Select(x => x.Value) : projects.EnumerateArray())
            {
                var managed = item.TryGetProperty("managed_by", out var mb) && mb.GetString()?.Equals("devfleet", StringComparison.OrdinalIgnoreCase) == true;
                var projectId = item.TryGetProperty("project_id", out var id) ? id.GetString() ?? "" : "";
                var runtime = item.TryGetProperty("runtime_id", out var rid) ? rid.GetString() ?? "" : "";
                var slug = item.TryGetProperty("slug", out var s) ? s.GetString() ?? "" : "";
                var backup = FindLatestBackup(projectId, slug, runtime);
                result.Add(new VmRecord("Multipass Host Agent", runtime, projectId, managed, slug, backup.BackupId, backup.Sha256));
            }
            return result;
        }
        catch (JsonException) { return []; }
    }

    public BackupVerification CreateFreshBackup(VmRecord vm)
    {
        if (!vm.Owned || string.IsNullOrWhiteSpace(vm.ProjectId) || string.IsNullOrWhiteSpace(vm.RuntimeId) || string.IsNullOrWhiteSpace(vm.Slug))
            throw new InvalidOperationException("Fresh safety backup requires an exact owned project and runtime identity.");
        using var config = JsonDocument.Parse(File.ReadAllText(Path.Combine(_root, "config.json")));
        var prefix = config.RootElement.TryGetProperty("ListenPrefix", out var lp) ? lp.GetString() : "http://127.0.0.1:8791/";
        var tokenPath = config.RootElement.TryGetProperty("TokenPath", out var tp) ? tp.GetString() : null;
        if (string.IsNullOrWhiteSpace(tokenPath) || !File.Exists(tokenPath)) throw new InvalidOperationException("Host Agent token path is unavailable; fresh safety backup is blocked.");
        var backupBody = JsonSerializer.SerializeToUtf8Bytes(new { operation = "backup", slug = vm.Slug, project_id = vm.ProjectId, runtime_id = vm.RuntimeId });
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(BuildHostAgentBaseUri(prefix), $"v1/project-vms/{Uri.EscapeDataString(vm.RuntimeId)}/backup"));
        request.Content = new ByteArrayContent(backupBody);
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        AddRequestAuthentication(request, backupBody, File.ReadAllText(tokenPath).Trim(), config.RootElement.TryGetProperty("HostName", out var hostName) ? hostName.GetString() ?? "" : "");
        using var response = _http.Send(request);
        var bodyBytes = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
        VerifyResponseAuthentication(request, response, bodyBytes, File.ReadAllText(tokenPath).Trim(), config.RootElement.TryGetProperty("HostName", out var responseHostName) ? responseHostName.GetString() ?? "" : "");
        var body = Encoding.UTF8.GetString(bodyBytes);
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"Host Agent rejected fresh safety backup ({(int)response.StatusCode}): {body}");
        using var document = JsonDocument.Parse(body); var root = document.RootElement;
        var id = root.TryGetProperty("backup_id", out var bid) ? bid.GetString() ?? "" : "";
        var sha = root.TryGetProperty("backup_sha256", out var sh) ? sh.GetString() ?? "" : "";
        var status = root.TryGetProperty("backup_status", out var st) ? st.GetString() ?? "" : "";
        if (!status.Equals("verified", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(id) || !Regex.IsMatch(sha, "^[0-9a-fA-F]{64}$"))
            throw new InvalidDataException("Host Agent fresh safety backup did not return a verified identity-bound backup reference.");
        if (!root.TryGetProperty("backup_reference", out var reference) || reference.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("Host Agent fresh safety backup omitted its opaque provider reference.");
        var providerReference = new BackupReference(
            reference.GetProperty("provider").GetString() ?? "",
            reference.GetProperty("backup_id").GetString() ?? "",
            reference.GetProperty("project_id").GetString() ?? "",
            reference.GetProperty("slug").GetString() ?? "",
            reference.GetProperty("runtime_id").GetString() ?? "",
            reference.GetProperty("host_id").GetString() ?? "",
            reference.GetProperty("archive_sha256").GetString() ?? "",
            reference.GetProperty("archive_bytes").GetInt64(),
            reference.GetProperty("manifest_sha256").GetString() ?? "",
            reference.GetProperty("created_at").GetString() ?? "",
            reference.GetProperty("consistency_level").GetString() ?? "");
        if (!providerReference.Provider.Equals("multipass-host-agent", StringComparison.OrdinalIgnoreCase) || !providerReference.BackupId.Equals(id, StringComparison.OrdinalIgnoreCase) || !providerReference.ProjectId.Equals(vm.ProjectId, StringComparison.OrdinalIgnoreCase) || !providerReference.Slug.Equals(vm.Slug, StringComparison.OrdinalIgnoreCase) || !providerReference.RuntimeId.Equals(vm.RuntimeId, StringComparison.OrdinalIgnoreCase) || !providerReference.ArchiveSha256.Equals(sha, StringComparison.OrdinalIgnoreCase) || providerReference.ArchiveBytes < 0 || !Regex.IsMatch(providerReference.ManifestSha256, "^[0-9a-fA-F]{64}$"))
            throw new InvalidDataException("Host Agent backup reference identity or hash binding is invalid.");
        return new BackupVerification(vm.ProjectId, id, "", sha, sha, true, true, DateTime.UtcNow, providerReference);
    }

    public void DeleteExact(VmRecord vm)
    {
        if (!vm.Owned || string.IsNullOrWhiteSpace(vm.Slug) || string.IsNullOrWhiteSpace(vm.BackupId) || string.IsNullOrWhiteSpace(vm.BackupSha256))
            throw new InvalidOperationException("Host Agent destruction requires an owned project, exact slug, and selected verified backup.");
        var configPath = Path.Combine(_root, "config.json");
        using var config = JsonDocument.Parse(File.ReadAllText(configPath));
        var prefix = config.RootElement.TryGetProperty("ListenPrefix", out var lp) ? lp.GetString() : "http://127.0.0.1:8791/";
        var tokenPath = config.RootElement.TryGetProperty("TokenPath", out var tp) ? tp.GetString() : null;
        if (string.IsNullOrWhiteSpace(tokenPath) || !File.Exists(tokenPath)) throw new InvalidOperationException("Host Agent token path is unavailable; destruction is blocked.");
        var destroyBody = JsonSerializer.SerializeToUtf8Bytes(new { operation = "destroy", slug = vm.Slug, project_id = vm.ProjectId, confirm_slug = vm.Slug, confirm_phrase = $"DESTROY {vm.Slug}", backup_verified = true, backup_id = vm.BackupId, backup_sha256 = vm.BackupSha256 });
        using var request = new HttpRequestMessage(HttpMethod.Delete, new Uri(BuildHostAgentBaseUri(prefix), $"v1/project-vms/{Uri.EscapeDataString(vm.RuntimeId)}/destroy"));
        request.Content = new ByteArrayContent(destroyBody);
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        AddRequestAuthentication(request, destroyBody, File.ReadAllText(tokenPath).Trim(), config.RootElement.TryGetProperty("HostName", out var hostName) ? hostName.GetString() ?? "" : "");
        using var response = _http.Send(request);
        var bodyBytes = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
        VerifyResponseAuthentication(request, response, bodyBytes, File.ReadAllText(tokenPath).Trim(), config.RootElement.TryGetProperty("HostName", out var responseHostName) ? responseHostName.GetString() ?? "" : "");
        var body = Encoding.UTF8.GetString(bodyBytes);
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"Host Agent rejected exact project destruction ({(int)response.StatusCode}): {body}");
        if (!body.Contains("\"state\":\"destroyed\"", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Host Agent destruction response did not prove destroyed state.");
    }

    private static Uri BuildHostAgentBaseUri(string? configuredPrefix)
    {
        var prefix = string.IsNullOrWhiteSpace(configuredPrefix) ? "http://127.0.0.1:8791/" : configuredPrefix.Trim();
        foreach (var scheme in new[] { "http://", "https://" })
        foreach (var wildcard in new[] { "+", "*" })
        {
            var marker = scheme + wildcard + ":";
            if (prefix.StartsWith(marker, StringComparison.OrdinalIgnoreCase))
            {
                prefix = scheme + "127.0.0.1:" + prefix[marker.Length..];
                break;
            }
        }
        if (!Uri.TryCreate(prefix.TrimEnd('/') + "/", UriKind.Absolute, out var uri) || uri is null || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) || !string.IsNullOrEmpty(uri.UserInfo))
            throw new InvalidOperationException("Host Agent listen prefix is not a valid local HTTP endpoint.");
        return uri;
    }

    private static void AddRequestAuthentication(HttpRequestMessage request, byte[] body, string key, string expectedHost)
    {
        if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(expectedHost)) throw new InvalidOperationException("Host Agent request authentication configuration is incomplete.");
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(18)).ToLowerInvariant();
        var prefix = Encoding.UTF8.GetBytes($"{request.Method.Method.ToUpperInvariant()}\n{request.RequestUri!.AbsolutePath}\n{timestamp}\n{nonce}\n");
        var suffix = Encoding.UTF8.GetBytes($"\n{expectedHost}");
        var material = new byte[prefix.Length + body.Length + suffix.Length];
        Buffer.BlockCopy(prefix, 0, material, 0, prefix.Length);
        Buffer.BlockCopy(body, 0, material, prefix.Length, body.Length);
        Buffer.BlockCopy(suffix, 0, material, prefix.Length + body.Length, suffix.Length);
        var signature = Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(key), material)).ToLowerInvariant();
        request.Headers.TryAddWithoutValidation("X-DevFleet-Host-Timestamp", timestamp);
        request.Headers.TryAddWithoutValidation("X-DevFleet-Host-Nonce", nonce);
        request.Headers.TryAddWithoutValidation("X-DevFleet-Host-Expected", expectedHost);
        request.Headers.TryAddWithoutValidation("X-DevFleet-Host-Signature", signature);
    }

    private static void VerifyResponseAuthentication(HttpRequestMessage request, HttpResponseMessage response, byte[] body, string key, string expectedHost)
    {
        if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(expectedHost)) throw new InvalidOperationException("Host Agent response authentication configuration is incomplete.");
        var timestamp = request.Headers.GetValues("X-DevFleet-Host-Timestamp").Single();
        var nonce = request.Headers.GetValues("X-DevFleet-Host-Nonce").Single();
        var provided = response.Headers.TryGetValues("X-DevFleet-Host-Response-Signature", out var values) ? values.SingleOrDefault() : null;
        var material = BuildAuthMaterial(request.Method.Method, request.RequestUri!.AbsolutePath, timestamp, nonce, ((int)response.StatusCode).ToString(System.Globalization.CultureInfo.InvariantCulture), body, expectedHost);
        var expected = Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(key), material)).ToLowerInvariant();
        var left = Encoding.ASCII.GetBytes(expected); var right = Encoding.ASCII.GetBytes((provided ?? "").ToLowerInvariant());
        if (left.Length != right.Length || !CryptographicOperations.FixedTimeEquals(left, right)) throw new InvalidDataException("Host Agent response authentication failed.");
    }

    private static byte[] BuildAuthMaterial(string method, string path, string timestamp, string nonce, string status, byte[] body, string expectedHost)
    {
        var parts = new[] { Encoding.UTF8.GetBytes(method.ToUpperInvariant()), Encoding.UTF8.GetBytes("\n"), Encoding.UTF8.GetBytes(path), Encoding.UTF8.GetBytes("\n"), Encoding.UTF8.GetBytes(timestamp), Encoding.UTF8.GetBytes("\n"), Encoding.UTF8.GetBytes(nonce), Encoding.UTF8.GetBytes("\n"), Encoding.UTF8.GetBytes(status), Encoding.UTF8.GetBytes("\n") , body, Encoding.UTF8.GetBytes("\n"), Encoding.UTF8.GetBytes(expectedHost) };
        var length = parts.Sum(part => part.Length); var material = new byte[length]; var offset = 0;
        foreach (var part in parts) { Buffer.BlockCopy(part, 0, material, offset, part.Length); offset += part.Length; }
        return material;
    }

    private (string BackupId, string Sha256) FindLatestBackup(string projectId, string slug, string runtime)
    {
        var backupRoot = Path.Combine(_root, "backups");
        foreach (var manifest in Directory.Exists(backupRoot) ? Directory.EnumerateFiles(backupRoot, "*.json").OrderByDescending(File.GetLastWriteTimeUtc) : Enumerable.Empty<string>())
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(manifest)); var r = doc.RootElement;
                if (r.TryGetProperty("project_id", out var pid) && pid.GetString() == projectId && r.TryGetProperty("slug", out var sl) && sl.GetString() == slug && r.TryGetProperty("runtime_id", out var rt) && rt.GetString() == runtime)
                    return (r.TryGetProperty("backup_id", out var bid) ? bid.GetString() ?? "" : Path.GetFileNameWithoutExtension(manifest), r.TryGetProperty("archive_sha256", out var sh) ? sh.GetString() ?? "" : "");
            }
            catch (JsonException) { }
        }
        return ("", "");
    }
}

public sealed class VmOwnershipService
{
    private readonly IVmProvider _provider;
    public VmOwnershipService(IVmProvider provider) => _provider = provider;
    public void DeleteOwnedExact(string projectId, string runtimeId, Action<string>? progress = null)
        => DeleteOwnedExact(projectId, runtimeId, null, progress);
    public void DeleteOwnedExact(string projectId, string runtimeId, BackupVerification? selectedBackup, Action<string>? progress = null)
    {
        var before = _provider.Discover().ToArray();
        var vm = before.SingleOrDefault(x => x.ProjectId.Equals(projectId, StringComparison.OrdinalIgnoreCase) && x.RuntimeId.Equals(runtimeId, StringComparison.OrdinalIgnoreCase));
        if (vm is null || !vm.Owned) throw new InvalidOperationException($"No independently owned VM matched project={projectId}, runtime={runtimeId}.");
        if (selectedBackup is not null)
        {
            if (!selectedBackup.IsVerified || !selectedBackup.ProjectId.Equals(projectId, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Exact selected backup binding is invalid.");
            vm = vm with { BackupId = selectedBackup.BackupId, BackupSha256 = selectedBackup.ActualSha256 };
            progress?.Invoke($"Exact selected backup bound: {selectedBackup.BackupId} sha256={selectedBackup.ActualSha256}");
        }
        _provider.DeleteExact(vm);
        progress?.Invoke($"Provider-aware exact deletion verified: {vm.Provider} {vm.RuntimeId}");
        var unrelated = before.Where(x => !x.RuntimeId.Equals(runtimeId, StringComparison.OrdinalIgnoreCase)).Select(x => x.RuntimeId).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (_provider.Discover().Where(x => unrelated.Contains(x.RuntimeId)).Count() != unrelated.Count) throw new InvalidOperationException("Unrelated VM inventory changed during exact deletion.");
    }

    public BackupVerification CreateFreshSafetyBackup(DiscoveredProject project, Action<string>? progress = null)
    {
        var vm = _provider.Discover().SingleOrDefault(x => x.ProjectId.Equals(project.ProjectId, StringComparison.OrdinalIgnoreCase) && x.RuntimeId.Equals(project.RuntimeId, StringComparison.OrdinalIgnoreCase));
        if (vm is null || !vm.Owned) throw new InvalidOperationException($"No independently owned VM matched project={project.ProjectId}, runtime={project.RuntimeId}.");
        var backup = _provider.CreateFreshBackup(vm);
        if (!backup.IsVerified || !backup.ProjectId.Equals(project.ProjectId, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Fresh safety backup identity verification failed.");
        progress?.Invoke($"Fresh Factory Reset safety backup bound: {backup.BackupId} sha256={backup.ActualSha256}");
        return backup;
    }
}

public sealed class TransactionService
{
    private readonly Stack<(string Name, Action Rollback)> _rollback = new();
    private readonly InstallerLogger _logger;
    public TransactionService(InstallerLogger logger) => _logger = logger;
    public void Execute(string name, Action action, Action rollback, Action<string>? progress = null)
    {
        _logger.Write($"step={name} state=planned"); progress?.Invoke($"Planned: {name}");
        action(); _rollback.Push((name, rollback)); _logger.Write($"step={name} state=verified"); progress?.Invoke($"Verified: {name}");
    }
    public void Rollback(Action<string>? progress = null)
    {
        while (_rollback.Count > 0)
        {
            var step = _rollback.Pop();
            try { step.Rollback(); _logger.Write($"step={step.Name} state=rolled-back"); progress?.Invoke($"Rolled back: {step.Name}"); }
            catch (Exception ex) { _logger.Write($"step={step.Name} state=rollback-incomplete error={ex.Message}"); progress?.Invoke($"Rollback incomplete: {step.Name}"); }
        }
    }
}

public static class RebootCheckpointService
{
    // The supported Windows prerequisite graph has at most three legitimate
    // reboot boundaries (PowerShell/servicing, Hyper-V, and final servicing).
    // Keep this explicit and bounded: an unexpected fourth boundary fails
    // closed instead of becoming an unbounded reboot loop.
    public const int MaxRebootBoundaries = 3;
    public static string Path => System.IO.Path.Combine(AppPaths.InstallerRoot, "resume-checkpoint.json");
    private static string ConsumedPath(string transactionId) => System.IO.Path.Combine(AppPaths.InstallerRoot, "resume-consumed", $"{transactionId}.json");
    private static string ScriptStateRoot => TestEnvironment.IsTestProcess
        ? AppPaths.StateRoot
        : System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DevFleet");

    public static void PrepareScriptTransaction(InstallerPlan plan, string role)
    {
        var scriptRoot = ScriptStateRoot;
        Directory.CreateDirectory(scriptRoot);
        StateStore.WriteJsonAtomically(System.IO.Path.Combine(scriptRoot, "active-transaction.json"), new
        {
            transactionId = plan.TransactionId,
            payloadSha256 = PayloadManifest.PayloadSha256,
            action = plan.Mode.ToString(),
            role = role.Contains("Laptop", StringComparison.OrdinalIgnoreCase) ? "Laptop" : "Desktop",
            preparedUtc = DateTime.UtcNow.ToString("O")
        });
    }

    private static string[] ReadCompletedStages(InstallerPlan plan, string role)
    {
        var normalizedRole = role.Contains("Laptop", StringComparison.OrdinalIgnoreCase) ? "Laptop" : "Desktop";
        var activePath = System.IO.Path.Combine(ScriptStateRoot, "active-transaction.json");
        if (!File.Exists(activePath)) throw new InvalidDataException("The active DevFleet transaction record is missing; refusing to advance reboot progress.");
        using var activeDocument = JsonDocument.Parse(File.ReadAllText(activePath));
        var active = activeDocument.RootElement;
        if (active.GetProperty("transactionId").GetString() != plan.TransactionId || active.GetProperty("payloadSha256").GetString() != PayloadManifest.PayloadSha256 || active.GetProperty("action").GetString() != plan.Mode.ToString() || active.GetProperty("role").GetString() != normalizedRole) throw new InvalidDataException("The active DevFleet transaction record does not match the reboot checkpoint.");
        var roots = new[] { AppPaths.StateRoot, ScriptStateRoot }
            .Where(Directory.Exists)
            .Distinct(StringComparer.OrdinalIgnoreCase);
        var allowed = normalizedRole == "Desktop"
            ? new Regex("^stage-(prereqs-Desktop|windows-tailscale|host-agent|compute-devfleet-primary)$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)
            : new Regex("^stage-(prereqs-Laptop|windows-tailscale|host-agent|compute-devfleet-failover|vault)$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        return roots.SelectMany(root => Directory.EnumerateFiles(root, "stage-*.complete", SearchOption.TopDirectoryOnly))
            .Select(path => (path, name: System.IO.Path.GetFileNameWithoutExtension(path)))
            .Where(item => allowed.IsMatch(item.name))
            .Where(item => {
                try {
                    using var marker = JsonDocument.Parse(File.ReadAllText(item.path));
                    var value = marker.RootElement;
                    return value.GetProperty("transactionId").GetString() == plan.TransactionId && value.GetProperty("payloadSha256").GetString() == PayloadManifest.PayloadSha256 && value.GetProperty("action").GetString() == plan.Mode.ToString() && value.GetProperty("role").GetString() == normalizedRole && value.GetProperty("stage").GetString() == item.name;
                } catch { return false; }
            })
            .Select(item => item.name)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string ResumeStage(IEnumerable<string> completedStages)
    {
        var completed = completedStages.ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (completed.Count == 0) return "bootstrap-entrypoint";
        if (!completed.Any(x => x.Equals("stage-prereqs-Desktop", StringComparison.OrdinalIgnoreCase) || x.Equals("stage-prereqs-Laptop", StringComparison.OrdinalIgnoreCase))) return "prerequisites";
        if (!completed.Contains("stage-host-agent")) return "host-agent";
        if (completed.Contains("stage-prereqs-Laptop"))
        {
            if (!completed.Contains("stage-compute-devfleet-failover")) return "compute-devfleet-failover";
            if (!completed.Contains("stage-vault")) return "vault";
        }
        else if (!completed.Contains("stage-compute-devfleet-primary")) return "compute-devfleet-primary";
        return "finalize";
    }

    private static void ValidateCompletedStages(JsonElement root, string role, out string[] completedStages)
    {
        completedStages = root.TryGetProperty("completedStages", out var stages)
            ? stages.EnumerateArray().Select(x => x.GetString() ?? "").ToArray()
            : [];
        var normalizedRole = role.Contains("Laptop", StringComparison.OrdinalIgnoreCase) ? "Laptop" : "Desktop";
        var allowed = normalizedRole == "Desktop"
            ? new Regex("^stage-(prereqs-Desktop|windows-tailscale|host-agent|compute-devfleet-primary)$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)
            : new Regex("^stage-(prereqs-Laptop|windows-tailscale|host-agent|compute-devfleet-failover|vault)$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
        if (completedStages.Any(x => string.IsNullOrWhiteSpace(x) || !allowed.IsMatch(x) || x.Contains(System.IO.Path.DirectorySeparatorChar) || x.Contains(System.IO.Path.AltDirectorySeparatorChar)) ||
            completedStages.Length != completedStages.Distinct(StringComparer.OrdinalIgnoreCase).Count())
            throw new InvalidDataException("A reboot checkpoint contains invalid or duplicate completed stage identities.");
        var completed = completedStages.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var prereq = $"stage-prereqs-{normalizedRole}";
        if (completed.Contains("stage-host-agent") && !completed.Contains(prereq) ||
            completed.Any(x => x.StartsWith("stage-compute-", StringComparison.OrdinalIgnoreCase) || x.Equals("stage-vault", StringComparison.OrdinalIgnoreCase)) && !completed.Contains("stage-host-agent"))
            throw new InvalidDataException("A reboot checkpoint contains out-of-order completed stage progress.");
        var expected = ResumeStage(completedStages);
        var stored = root.TryGetProperty("resumeStage", out var stage) ? stage.GetString() : null;
        if (!string.Equals(stored, expected, StringComparison.Ordinal)) throw new InvalidDataException("A reboot checkpoint has inconsistent durable stage progress.");
    }

    private static void ValidateIdentity(JsonElement root, InstallerPlan plan, string role, bool requirePlanTransaction, out string transactionId, out int generation)
    {
        var state = root.GetProperty("state").GetString();
        var action = root.GetProperty("action").GetString();
        var checkpointRole = root.GetProperty("role").GetString();
        var payload = root.GetProperty("payloadSha256").GetString();
        transactionId = root.GetProperty("transactionId").GetString() ?? "";
        generation = root.GetProperty("checkpointGeneration").GetInt32();
        var installerVersion = root.GetProperty("installerVersion").GetString();
        var devFleetVersion = root.GetProperty("devFleetVersion").GetString();
        var declaredMaximum = root.GetProperty("maxRebootBoundaries").GetInt32();
        var generationOk = generation >= 1 && generation <= MaxRebootBoundaries;
        if (state != "waiting-for-reboot" || action != plan.Mode.ToString() || !string.Equals(checkpointRole, role, StringComparison.OrdinalIgnoreCase) || !string.Equals(payload, PayloadManifest.PayloadSha256, StringComparison.OrdinalIgnoreCase) || !string.Equals(installerVersion, PayloadManifest.InstallerVersion, StringComparison.Ordinal) || !string.Equals(devFleetVersion, PayloadManifest.DevFleetVersion, StringComparison.Ordinal) || declaredMaximum != MaxRebootBoundaries || !generationOk || !Regex.IsMatch(transactionId, "^[0-9a-f]{32}$", RegexOptions.CultureInvariant) || (requirePlanTransaction && !string.Equals(transactionId, plan.TransactionId, StringComparison.Ordinal)) || File.Exists(ConsumedPath(transactionId)))
            throw new InvalidDataException("A stale, tampered, or candidate-mismatched reboot checkpoint is present; refusing resume.");
        ValidateCompletedStages(root, role, out _);
    }

    public static void Write(InstallerPlan plan, string role, string? recovery, Action<string>? progress = null)
    {
        var generation = 1;
        var createdUtc = DateTime.UtcNow.ToString("O");
        if (File.Exists(Path))
        {
            using var prior = JsonDocument.Parse(File.ReadAllText(Path));
            ValidateIdentity(prior.RootElement, plan, role, requirePlanTransaction: true, out _, out var previousGeneration);
            generation = previousGeneration + 1;
            if (prior.RootElement.TryGetProperty("createdUtc", out var created) && created.GetString() is { Length: > 0 } value) createdUtc = value;
        }
        if (generation > MaxRebootBoundaries) throw new InvalidOperationException($"DevFleet installation exceeded the supported reboot boundary limit ({MaxRebootBoundaries}); refusing another reboot.");
        var completedStages = ReadCompletedStages(plan, role);
        var resumeStage = ResumeStage(completedStages);
        StateStore.WriteJsonAtomically(Path, new { state = "waiting-for-reboot", action = plan.Mode.ToString(), plan.TransactionId, installerVersion = PayloadManifest.InstallerVersion, devFleetVersion = PayloadManifest.DevFleetVersion, payloadSha256 = PayloadManifest.PayloadSha256, role, completedStages, resumeStage, recoveryPath = recovery, checkpointGeneration = generation, maxRebootBoundaries = MaxRebootBoundaries, createdUtc, updatedUtc = DateTime.UtcNow.ToString("O") });
        progress?.Invoke($"Safe reboot checkpoint persisted: {Path}");
    }

    public static bool ValidateIfPresent(InstallerPlan plan, string role, Action<string>? progress = null)
    {
        if (!File.Exists(Path)) return false;
        using var document = JsonDocument.Parse(File.ReadAllText(Path));
        var root = document.RootElement;
        ValidateIdentity(root, plan, role, requirePlanTransaction: true, out _, out _);
        progress?.Invoke("Verified durable reboot checkpoint; resuming the same action and candidate without clearing recovery state.");
        return true;
    }

    public static bool BindPlanIfPresent(InstallerPlan plan, string role, Action<string>? progress = null)
    {
        if (!File.Exists(Path)) return false;
        using var document = JsonDocument.Parse(File.ReadAllText(Path));
        var root = document.RootElement;
        var transactionId = root.GetProperty("transactionId").GetString() ?? "";
        ValidateIdentity(root, plan, role, requirePlanTransaction: false, out _, out _);
        plan.TransactionId = transactionId;
        progress?.Invoke("Bound the reviewed plan to the durable reboot transaction and generation.");
        return true;
    }

    public static void Consume(InstallerPlan plan, string role, Action<string>? progress = null)
    {
        if (!File.Exists(Path)) return;
        using var document = JsonDocument.Parse(File.ReadAllText(Path));
        var root = document.RootElement;
        var transactionId = root.GetProperty("transactionId").GetString() ?? "";
        var generation = root.GetProperty("checkpointGeneration").GetInt32();
        if (!Regex.IsMatch(transactionId, "^[0-9a-f]{32}$", RegexOptions.CultureInvariant) || generation < 1 || generation > MaxRebootBoundaries) throw new InvalidDataException("Refusing to consume an invalid reboot checkpoint identity.");
        ValidateIdentity(root, plan, role, requirePlanTransaction: true, out _, out _);
        var checkpointPayload = root.GetProperty("payloadSha256").GetString();
        if (!string.Equals(checkpointPayload, PayloadManifest.PayloadSha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Refusing to consume a checkpoint for a different payload.");
        StateStore.WriteJsonAtomically(ConsumedPath(transactionId), new { transactionId, checkpointGeneration = generation, action = root.GetProperty("action").GetString(), role = root.GetProperty("role").GetString(), installerVersion = root.GetProperty("installerVersion").GetString(), devFleetVersion = root.GetProperty("devFleetVersion").GetString(), payloadSha256 = checkpointPayload, completedStages = root.GetProperty("completedStages"), resumeStage = root.GetProperty("resumeStage").GetString(), consumedUtc = DateTime.UtcNow.ToString("O") });
        File.Delete(Path);
        var activePath = System.IO.Path.Combine(ScriptStateRoot, "active-transaction.json");
        if (File.Exists(activePath))
        {
            try { using var active = JsonDocument.Parse(File.ReadAllText(activePath)); if (active.RootElement.GetProperty("transactionId").GetString() == transactionId) File.Delete(activePath); } catch { }
        }
        progress?.Invoke("Durable reboot checkpoint consumed after verified completion.");
    }
}

public static class ElevationService
{
    public static bool IsAdministrator => OperatingSystem.IsWindows() && new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    public static Process? RelaunchVerified(string role, InstallerMode mode, bool deferNetworkPairing = false)
    {
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("The verified installer executable path is unavailable.");
        return Process.Start(new ProcessStartInfo { FileName = exe, Verb = "runas", UseShellExecute = true, Arguments = $"--elevated-resume --action {mode} --role \"{role}\"{(deferNetworkPairing ? " --defer-network-pairing" : "")}" });
    }
}

public static class LifecycleEngine
{
    public static InstallerExecutionReport? LastExecution { get; private set; }
    private static void AssertExactFactoryResetSelection(InstallerPlan plan)
    {
        if (plan.Mode != InstallerMode.FactoryReset || !plan.ProjectDataSelected) return;
        var requested = plan.SelectedProjectIds.Select(x => x.Trim()).Where(x => x.Length > 0).ToArray();
        if (requested.Length != requested.Distinct(StringComparer.OrdinalIgnoreCase).Count()) throw new InvalidOperationException("Factory Reset blocked: the reviewed execution set contains duplicate project IDs.");
        var reviewedIds = plan.SelectedProjects.Select(x => x.ProjectId.Trim()).Where(x => x.Length > 0).ToArray();
        if (reviewedIds.Length != requested.Length || reviewedIds.Length != reviewedIds.Distinct(StringComparer.OrdinalIgnoreCase).Count() || !reviewedIds.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(requested))
            throw new InvalidOperationException("Factory Reset blocked: the reviewed project records do not exactly match the requested execution set. Review and confirm again.");
        var current = new ProjectDiscoveryService().Discover();
        var currentSelected = current.Where(x => requested.Contains(x.ProjectId, StringComparer.OrdinalIgnoreCase)).ToArray();
        if (currentSelected.Length != requested.Length || !currentSelected.Select(x => x.ProjectId).ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(requested)) throw new InvalidOperationException("Factory Reset blocked: the exact reviewed project selection changed before execution. Review and confirm again.");
        foreach (var reviewed in plan.SelectedProjects)
        {
            var now = currentSelected.SingleOrDefault(x => x.ProjectId.Equals(reviewed.ProjectId, StringComparison.OrdinalIgnoreCase));
            if (now is null || !now.Slug.Equals(reviewed.Slug, StringComparison.Ordinal) || !now.RuntimeId.Equals(reviewed.RuntimeId, StringComparison.Ordinal) || !now.OwnershipStatus.Equals("VERIFIED", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"Factory Reset blocked: reviewed project identity or ownership drifted for {reviewed.ProjectId}. Review and confirm again.");
        }
    }
    public static string Execute(InstallerPlan plan, string role, Action<string>? progress = null)
    {
        if (!plan.IsAllowed) throw new InvalidOperationException(string.Join(Environment.NewLine, plan.Blockers));
        if (plan.IsMutation && !ElevationService.IsAdministrator && !TestEnvironment.IsTestProcess)
            throw new InvalidOperationException("Machine-wide mutation requires UAC elevation. Relaunch the same verified installer with runas before executing.");
        var logger = new InstallerLogger();
        var tx = new TransactionService(logger);
        var ledger = StateStore.ReadLedger();
        var previousLedger = ledger;
        string? recovery = null;
        string? controlPlaneSnapshot = null;
        try
        {
            var resumed = RebootCheckpointService.ValidateIfPresent(plan, role, progress);
            if (plan.Mode is InstallerMode.Diagnostics or InstallerMode.RecoveryPackage) return PreflightService.ToText(PreflightService.Run());
            if (plan.Mode is InstallerMode.CleanReinstall or InstallerMode.Uninstall or InstallerMode.FactoryReset)
                recovery = RecoveryService.Create(plan.TransactionId, progress);
            if (plan.Mode == InstallerMode.CleanReinstall)
                controlPlaneSnapshot = ControlPlaneSnapshotService.Capture(plan.TransactionId, progress);
            if (plan.Mode == InstallerMode.FactoryReset && plan.ProjectDataSelected)
            {
                if (plan.SelectedProjects.Count == 0) throw new InvalidOperationException("Factory Reset blocked: no individual project is selected.");
                AssertExactFactoryResetSelection(plan);
                var factoryReset = new FactoryResetService(new BackupVerificationService(), new VmOwnershipService(new MultipassHostAgentProvider()));
                foreach (var project in plan.SelectedProjects) factoryReset.DeleteSelected(project, progress);
            }
            if (plan.Mode is InstallerMode.Uninstall or InstallerMode.FactoryReset)
                CleanupJournalService.Execute(plan.Mode.ToString(), plan.TransactionId, BuildMonotonicCleanupStages(ledger, progress), progress, ledger.InstallTimestampUtc, ledger.PackageSha256);
            else if (plan.Mode == InstallerMode.CleanReinstall)
                progress?.Invoke("Clean Reinstall is staged transactionally; the previous control plane remains available until replacement verification.");
            if (plan.Mode is InstallerMode.FreshInstall or InstallerMode.Repair or InstallerMode.CleanReinstall or InstallerMode.LocalUpdate)
            {
                RebootCheckpointService.PrepareScriptTransaction(plan, role);
                var staged = PayloadService.StageVerifiedPayload(plan.TransactionId, progress);
                var releaseRoot = PayloadService.ExtractVerifiedPayload(staged, plan.TransactionId, progress);
                var fixture = TestEnvironment.IsTestProcess && string.Equals(Environment.GetEnvironmentVariable("DEVFLEET_SETUP_FIXTURE_MODE"), "1", StringComparison.Ordinal);
                if (plan.Mode == InstallerMode.Repair)
                {
                    var report = new RepairService(new InstallService(fixture ? new RecordingProcessRunner() : null)).Repair(releaseRoot, role, progress, plan.DeferNetworkPairing, plan.AcknowledgeRootfulDocker);
                    LastExecution = report;
                    progress?.Invoke($"Real repair entry-point completion verified: {string.Join(" -> ", report.Stages)}");
                }
                else
                {
                    var report = new InstallService(fixture ? new RecordingProcessRunner() : null).Run(releaseRoot, role, plan.Mode.ToString(), progress, plan.DeferNetworkPairing, plan.AcknowledgeRootfulDocker);
                    LastExecution = report;
                    if (report.ExitCode == 3010) throw new RebootRequiredException("DevFleet installation reached a safe reboot checkpoint.");
                    progress?.Invoke($"Real installer stage map complete: {string.Join(" -> ", report.Stages)}");
                }
                ledger = BuildLedger(releaseRoot, role, recovery);
                InstallStableLauncher(ledger, progress);
                CreateInstalledAppEntry(ledger); CreateShortcuts(ledger, progress);
                StateStore.WriteLedger(ledger); progress?.Invoke("Ownership ledger committed after verification.");
            }
            if (plan.Mode is InstallerMode.Uninstall or InstallerMode.FactoryReset)
            {
                foreach (var key in ledger.RegistryEntriesCreated) RemoveExactRegistryEntry(key, progress);
                File.Delete(AppPaths.LedgerPath);
            }
            logger.Write($"transaction={plan.TransactionId} state=completed");
            if (controlPlaneSnapshot is not null) ControlPlaneSnapshotService.Delete(controlPlaneSnapshot);
            RebootCheckpointService.Consume(plan, role, progress);
            return recovery ?? logger.LogPath;
        }
        catch (RebootRequiredException ex)
        {
            RebootCheckpointService.Write(plan, role, recovery, progress);
            logger.Write($"transaction={plan.TransactionId} state=waiting-for-reboot");
            progress?.Invoke($"Waiting for reboot: {ex.Message} Rerun DevFleet Setup to resume.");
            return recovery ?? logger.LogPath;
        }
        catch (Exception ex)
        {
            logger.Write($"transaction={plan.TransactionId} state=failed error={ex.Message}");
            if (plan.Mode is not (InstallerMode.Uninstall or InstallerMode.FactoryReset)) tx.Rollback(progress);
            if (controlPlaneSnapshot is not null)
            {
                ControlPlaneSnapshotService.Restore(controlPlaneSnapshot, progress);
                StateStore.WriteLedger(previousLedger);
            }
            throw;
        }
    }

    private static string JsonString(JsonElement value, string name) => value.TryGetProperty(name, out var property) ? property.ToString() : "";

    private static void ImportWindowsIntegrationOwnership(InstallLedger ledger)
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DevFleetHostAgent", "integration-ownership.json");
        if (!File.Exists(path)) return;
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        var root = document.RootElement;
        if (root.GetProperty("SchemaVersion").GetInt32() != 1) throw new InvalidDataException("Windows integration ownership schema is unsupported.");
        ledger.InstallationGeneration = JsonString(root, "InstallationGeneration");
        ledger.WindowsIntegrationOwnershipPath = path;
        var marker = JsonString(root, "Marker");
        foreach (var item in root.GetProperty("ScheduledTasks").EnumerateArray())
            ledger.WindowsIntegrations.Add(new OwnedWindowsIntegration("ScheduledTask", JsonString(item, "Name"), JsonString(item, "Generation"), JsonString(item, "Marker") is { Length: > 0 } taskMarker ? taskMarker : marker, Executable: JsonString(item, "Executable"), Arguments: JsonString(item, "Arguments"), Principal: JsonString(item, "Principal"), LogonType: JsonString(item, "LogonType"), RunLevel: JsonString(item, "RunLevel"), Description: JsonString(item, "Description")));
        foreach (var item in root.GetProperty("FirewallRules").EnumerateArray())
            ledger.WindowsIntegrations.Add(new OwnedWindowsIntegration("FirewallRule", JsonString(item, "Name"), JsonString(item, "Generation"), JsonString(item, "Marker") is { Length: > 0 } firewallMarker ? firewallMarker : marker, Description: JsonString(item, "Description"), DisplayName: JsonString(item, "DisplayName"), Group: JsonString(item, "Group"), Direction: JsonString(item, "Direction"), Action: JsonString(item, "Action"), Protocol: JsonString(item, "Protocol"), LocalPort: JsonString(item, "LocalPort"), InterfaceAlias: JsonString(item, "InterfaceAlias"), RemoteAddress: JsonString(item, "RemoteAddress"), Profile: JsonString(item, "Profile")));
        foreach (var item in root.GetProperty("Services").EnumerateArray())
            ledger.WindowsIntegrations.Add(new OwnedWindowsIntegration("Service", JsonString(item, "Name"), JsonString(item, "Generation"), JsonString(item, "Marker") is { Length: > 0 } serviceMarker ? serviceMarker : marker, ImagePath: JsonString(item, "ImagePath"), Account: JsonString(item, "Account"), StartMode: JsonString(item, "StartMode")));
    }

    private static InstallLedger BuildLedger(string releaseRoot, string role, string? recovery)
    {
        var ledger = new InstallLedger { Role = role, PackageSha256 = PayloadManifest.PayloadSha256, InstallTimestampUtc = DateTime.UtcNow.ToString("O") };
        ledger.FilesInstalled.AddRange(Directory.EnumerateFiles(releaseRoot, "*", SearchOption.AllDirectories));
        ledger.OwnedResources.Add(new OwnedResource("release", "DevFleet release payload", "DevFleetLedger", releaseRoot));
        if (recovery is not null) ledger.OwnedResources.Add(new OwnedResource("recovery", "Recovery package", "DevFleetLedger", recovery));
        foreach (var dependency in new DependencyService().DetectAll().Where(x => x.Found))
        {
            ledger.PreExistingPrerequisites.Add($"{dependency.Name} {dependency.Version}");
            ledger.ResolvedPrerequisitePaths.Add($"{dependency.Name}|{dependency.ExecutablePath}");
        }
        ledger.ManagedSshMarkers.Add("# BEGIN DEVFLEET MANAGED|# END DEVFLEET MANAGED");
        ledger.ManagedVsCodeFiles.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Code", "User", "devfleet-settings.reference.jsonc"));
        ImportWindowsIntegrationOwnership(ledger);
        OwnedPathSafety.ValidateLedger(ledger);
        return ledger;
    }

    private static void RemoveOwnedControlPlane(InstallLedger ledger, Action<string>? progress)
    {
        new WindowsOwnedIntegrationCleanupService().Cleanup(ledger, progress);
        RemoveManagedSshAndVsCode(ledger, progress);
        ScheduleSelfRemoval(progress);
        foreach (var file in ledger.FilesInstalled.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var full = Path.GetFullPath(file);
            if (OwnedPathSafety.IsUnderOwnedRoot(full, AppPaths.InstallRoot) && File.Exists(full)) { File.Delete(full); progress?.Invoke($"Removed proven-owned program file: {full}"); }
        }
        foreach (var shortcut in ledger.ShortcutsCreated.Where(File.Exists)) { File.Delete(shortcut); progress?.Invoke($"Removed DevFleet shortcut: {shortcut}"); }
        var shortcutRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs", "DevFleet");
        if (Directory.Exists(shortcutRoot) && !Directory.EnumerateFileSystemEntries(shortcutRoot).Any()) Directory.Delete(shortcutRoot);
        foreach (var reg in ledger.RegistryEntriesCreated) RemoveExactRegistryEntry(reg, progress);
    }

    private static IReadOnlyList<(string Name, Action Action)> BuildMonotonicCleanupStages(InstallLedger ledger, Action<string>? progress)
    {
        return [
            ("stop-and-remove-owned-integrations", () => new WindowsOwnedIntegrationCleanupService().Cleanup(ledger, progress)),
            ("remove-managed-ssh-and-vscode-integrations", () => RemoveManagedSshAndVsCode(ledger, progress)),
            ("schedule-owned-self-removal", () => ScheduleSelfRemoval(progress)),
            ("remove-owned-program-files", () => InstallerEngine.RemoveLedgerFiles(ledger, progress)),
            ("remove-owned-shortcuts", () => { foreach (var shortcut in ledger.ShortcutsCreated.Distinct(StringComparer.OrdinalIgnoreCase)) { if (File.Exists(shortcut)) File.Delete(shortcut); if (File.Exists(shortcut)) throw new IOException($"Owned shortcut remains after cleanup: {shortcut}"); progress?.Invoke($"Removed and verified DevFleet shortcut: {shortcut}"); } }),
            ("remove-owned-registry-entries", () => { foreach (var reg in ledger.RegistryEntriesCreated.Distinct(StringComparer.OrdinalIgnoreCase)) RemoveExactRegistryEntry(reg, progress); })
        ];
    }

    private static void RemoveManagedSshAndVsCode(InstallLedger ledger, Action<string>? progress)
    {
        var sshConfig = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh", "config");
        if (File.Exists(sshConfig))
        {
            var text = File.ReadAllText(sshConfig);
            foreach (var marker in ledger.ManagedSshMarkers)
            {
                var parts = marker.Split('|', 2); if (parts.Length != 2) continue;
                var pattern = $@"(?ms)^\s*{Regex.Escape(parts[0])}\s*$.*?^\s*{Regex.Escape(parts[1])}\s*$\r?\n?";
                text = Regex.Replace(text, pattern, "");
            }
            File.WriteAllText(sshConfig, text);
            var remaining = File.ReadAllText(sshConfig);
            foreach (var marker in ledger.ManagedSshMarkers)
            {
                var parts = marker.Split('|', 2); if (parts.Length != 2) continue;
                if (remaining.Contains(parts[0], StringComparison.Ordinal) || remaining.Contains(parts[1], StringComparison.Ordinal))
                    throw new IOException($"Managed SSH marker remains after cleanup: {sshConfig}");
            }
            progress?.Invoke($"Removed and verified only the DevFleet managed SSH block: {sshConfig}");
        }
        foreach (var file in ledger.ManagedVsCodeFiles)
        {
            var expectedRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Code", "User") + Path.DirectorySeparatorChar;
            var full = Path.GetFullPath(file); if (OwnedPathSafety.IsUnderOwnedRoot(full, expectedRoot) && Path.GetFileName(full).Equals("devfleet-settings.reference.jsonc", StringComparison.OrdinalIgnoreCase))
            {
                if (File.Exists(full)) File.Delete(full);
                if (File.Exists(full)) throw new IOException($"Managed VS Code file remains after cleanup: {full}");
                progress?.Invoke($"Removed and verified exact DevFleet VS Code reference file: {full}");
            }
        }
    }

    private static void ScheduleSelfRemoval(Action<string>? progress)
    {
        var current = Environment.ProcessPath;
        var target = Path.Combine(AppPaths.InstallRoot, "DevFleet.Setup.exe");
        if (string.IsNullOrWhiteSpace(current) || !Path.GetFullPath(current).Equals(Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase)) return;
        var helperDirectory = Path.Combine(AppPaths.CacheRoot, "SelfRemoval");
        SecureStagingService.EnsureDirectory(helperDirectory);
        var helper = Path.Combine(helperDirectory, $"DevFleet-Setup-Remove-{Guid.NewGuid():N}.ps1");
        using (var stream = new FileStream(helper, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        using (var writer = new StreamWriter(stream, new System.Text.UTF8Encoding(false)))
        {
            writer.Write("param([Parameter(Mandatory)][string]$Target,[Parameter(Mandatory)][string]$Helper)\n$ErrorActionPreference='Stop'\nStart-Sleep -Milliseconds 500\nif(Test-Path -LiteralPath $Target -PathType Leaf){Remove-Item -LiteralPath $Target -Force}\nif(Test-Path -LiteralPath $Helper -PathType Leaf){Remove-Item -LiteralPath $Helper -Force}\n");
            writer.Flush();
            stream.Flush(true);
        }
        var powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(powershell)) throw new FileNotFoundException("Windows PowerShell self-removal helper is unavailable.", powershell);
        var start = new ProcessStartInfo { FileName = powershell, UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden };
        foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", helper, "-Target", target, "-Helper", helper }) start.ArgumentList.Add(argument);
        if (Process.Start(start) is null) throw new InvalidOperationException("Unable to start the protected self-removal helper.");
        progress?.Invoke("Immediate exact self-removal helper scheduled from protected installer state with argument-bound paths.");
    }

    private static void RemoveExactRegistryEntry(string key, Action<string>? progress)
    {
        const string prefix = "HKLM\\";
        if (!key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) { progress?.Invoke($"Preserved non-machine registry entry outside owned scope: {key}"); return; }
        var subkey = key[prefix.Length..];
        using var root = Microsoft.Win32.Registry.LocalMachine;
        try
        {
            root.DeleteSubKeyTree(subkey, throwOnMissingSubKey: false);
            using var remaining = root.OpenSubKey(subkey);
            if (remaining is not null) throw new IOException($"Owned registry entry remains after cleanup: {key}");
            progress?.Invoke($"Removed and verified exact registry ownership: {key}");
        }
        catch (UnauthorizedAccessException ex) { throw new IOException($"Registry cleanup blocked by access policy: {key}", ex); }
    }

    private static void InstallStableLauncher(InstallLedger ledger, Action<string>? progress)
    {
        var current = Environment.ProcessPath; if (string.IsNullOrWhiteSpace(current) || !File.Exists(current)) return;
        Directory.CreateDirectory(AppPaths.InstallRoot);
        var target = Path.Combine(AppPaths.InstallRoot, "DevFleet.Setup.exe");
        if (!Path.GetFullPath(current).Equals(Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase)) File.Copy(current, target, true);
        ledger.FilesInstalled.Add(target); ledger.OwnedResources.Add(new OwnedResource("launcher", "DevFleet Setup", "DevFleetLedger", target)); progress?.Invoke($"Stable launcher target verified: {target}");
    }

    private static void CreateInstalledAppEntry(InstallLedger ledger)
    {
        using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\DevFleet");
        if (key is null) return;
        var exe = Path.Combine(AppPaths.InstallRoot, "DevFleet.Setup.exe");
        key.SetValue("DisplayName", "DevFleet"); key.SetValue("Publisher", "M-TechLabs"); key.SetValue("DisplayVersion", PayloadManifest.DevFleetVersion); key.SetValue("InstallLocation", AppPaths.InstallRoot); key.SetValue("UninstallString", $"\"{exe}\" --maintenance --action uninstall");
        ledger.RegistryEntriesCreated.Add(@"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\DevFleet");
    }

    private static void CreateShortcuts(InstallLedger ledger, Action<string>? progress)
    {
        var exe = Path.Combine(AppPaths.InstallRoot, "DevFleet.Setup.exe");
        if (!File.Exists(exe)) return;
        var start = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs", "DevFleet"); Directory.CreateDirectory(start);
        foreach (var item in new[] { ("DevFleet", "--maintenance"), ("DevFleet Maintenance", "--maintenance") })
        {
            var path = Path.Combine(start, item.Item1 + ".lnk");
            try
            {
                var type = Type.GetTypeFromProgID("WScript.Shell"); if (type is null) continue;
                dynamic shell = Activator.CreateInstance(type)!; dynamic shortcut = shell.CreateShortcut(path); shortcut.TargetPath = exe; shortcut.Arguments = item.Item2; shortcut.WorkingDirectory = AppPaths.InstallRoot; shortcut.Description = "DevFleet installed launcher"; shortcut.Save(); ledger.ShortcutsCreated.Add(path); progress?.Invoke($"Shortcut target verified: {path} -> {exe} {item.Item2}");
            }
            catch { progress?.Invoke($"Shortcut COM creation unavailable in this environment: {path}"); }
        }
    }
}
