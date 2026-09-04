using System.Formats.Tar;
using System.IO.Compression;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32;

namespace DevFleet.Setup;

internal static class TestEnvironment
{
    private static bool _enabled;
    private static string? _selfTestRoot;
    public static bool IsTestProcess => _enabled;
    internal static void EnableForTests() => _enabled = true;

    internal static void EnableForSelfTest(string root)
    {
        var full = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var temp = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var prefix = "DevFleet-Setup-SelfTest-";
        var leaf = Path.GetFileName(full);
        var parent = Directory.GetParent(full)?.FullName?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.Equals(parent, temp, StringComparison.OrdinalIgnoreCase) ||
            !leaf.StartsWith(prefix, StringComparison.Ordinal) ||
            !Guid.TryParseExact(leaf[prefix.Length..], "N", out _))
            throw new InvalidDataException("Self-test root must be a fresh DevFleet GUID directory directly beneath the process temporary directory.");
        _enabled = true;
        _selfTestRoot = full;
    }

    internal static bool IsAuthorizedSelfTestPath(string path)
    {
        if (string.IsNullOrWhiteSpace(_selfTestRoot)) return false;
        var full = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return full.Equals(_selfTestRoot, StringComparison.OrdinalIgnoreCase) ||
               full.StartsWith(_selfTestRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    internal static void ClearSelfTestRoot() => _selfTestRoot = null;
}

public static class AppPaths
{
    private static string? _selfTestInstallRoot;
    private static string? _selfTestStateRoot;
    public static string InstallRoot => _selfTestInstallRoot ?? (TestEnvironment.IsTestProcess ? Environment.GetEnvironmentVariable("DEVFLEET_SETUP_INSTALL_ROOT") : null)
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "M-TechLabs", "DevFleet");
    public static string StateRoot => _selfTestStateRoot ?? (TestEnvironment.IsTestProcess ? Environment.GetEnvironmentVariable("DEVFLEET_SETUP_STATE_ROOT") : null)
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "M-TechLabs", "DevFleet");
    public static string InstallerRoot => Path.Combine(StateRoot, "Installer");
    public static string CacheRoot => Path.Combine(StateRoot, "InstallerCache");
    public static string LogsRoot => Path.Combine(StateRoot, "Logs");
    public static string LedgerPath => Path.Combine(InstallerRoot, "install-state.json");

    internal static void ConfigureSelfTestRoots(string installRoot, string stateRoot)
    {
        _selfTestInstallRoot = Path.GetFullPath(installRoot);
        _selfTestStateRoot = Path.GetFullPath(stateRoot);
    }
}

public sealed class InstallLedger
{
    public string InstallerVersion { get; set; } = PayloadManifest.InstallerVersion;
    public string DevFleetVersion { get; set; } = PayloadManifest.DevFleetVersion;
    public string InstallTimestampUtc { get; set; } = DateTime.UtcNow.ToString("O");
    public string Role { get; set; } = "Standalone / unknown";
    public string PackageSha256 { get; set; } = PayloadManifest.PayloadSha256;
    public string InstallationGeneration { get; set; } = "";
    public string WindowsIntegrationOwnershipPath { get; set; } = "";
    public List<OwnedWindowsIntegration> WindowsIntegrations { get; set; } = [];
    public List<string> FilesInstalled { get; set; } = [];
    public List<string> ShortcutsCreated { get; set; } = [];
    public List<string> RegistryEntriesCreated { get; set; } = [];
    public List<OwnedResource> OwnedResources { get; set; } = [];
    public List<string> PrerequisitesInstalledByDevFleet { get; set; } = [];
    public List<string> PreExistingPrerequisites { get; set; } = [];
    public List<string> ManagedSshMarkers { get; set; } = [];
    public List<string> ManagedVsCodeFiles { get; set; } = [];
    public List<string> ResolvedPrerequisitePaths { get; set; } = [];
}

public static class OwnedPathSafety
{
    // Only primitive rights which can mutate a directory are security-relevant
    // here.  WriteData/CreateFiles and AppendData/CreateDirectories are enum
    // aliases; each is represented once.  Composite Modify and FullControl are
    // intentionally absent: their primitive mutation bits still intersect this
    // mask and are therefore rejected, while read-only ACEs cannot be promoted.
    public const FileSystemRights PrimitiveMutationRights =
        FileSystemRights.WriteData |
        FileSystemRights.AppendData |
        FileSystemRights.WriteExtendedAttributes |
        FileSystemRights.WriteAttributes |
        FileSystemRights.Delete |
        FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.ChangePermissions |
        FileSystemRights.TakeOwnership;

    public static bool HasPrimitiveMutationRights(FileSystemRights rights)
        => (rights & PrimitiveMutationRights) != 0;

    public static bool IsBroadUntrustedPrincipal(string identity)
        => identity.Equals("Everyone", StringComparison.OrdinalIgnoreCase)
            || identity.EndsWith("\\Users", StringComparison.OrdinalIgnoreCase)
            || identity.Equals("NT AUTHORITY\\Authenticated Users", StringComparison.OrdinalIgnoreCase);

    // Return the exact system trust root for an existing candidate.  The
    // caller must stop ACL traversal at this root; inspecting parents above a
    // trusted root (for example C:\\) would import unrelated machine policy.
    public static bool TryGetTrustedSystemRoot(string candidate, out string root)
    {
        root = "";
        try
        {
            var full = Path.GetFullPath(candidate).TrimEnd(Path.DirectorySeparatorChar);
            var roots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.Windows)
            }
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => Path.GetFullPath(x).TrimEnd(Path.DirectorySeparatorChar))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(x => full.StartsWith(x + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            .ToArray();
            if (roots.Length != 1) return false;
            root = roots[0];
            return true;
        }
        catch { return false; }
    }

    // WinGet is trusted only when the executable is the direct child of one
    // physical, approved WindowsApps package root.  AppX identity is supplied
    // by the caller so this structural predicate is independently testable.
    public static bool IsExactWindowsAppxPackageCandidate(string executable, string packageRoot, string approvedWindowsAppsRoot, string packageName, string publisherId)
    {
        try
        {
            if (!packageName.Equals("Microsoft.DesktopAppInstaller", StringComparison.OrdinalIgnoreCase) || !publisherId.Equals("8wekyb3d8bbwe", StringComparison.OrdinalIgnoreCase)) return false;
            if (executable.Contains("..", StringComparison.Ordinal) || packageRoot.Contains("..", StringComparison.Ordinal) || approvedWindowsAppsRoot.Contains("..", StringComparison.Ordinal)) return false;
            var full = Path.GetFullPath(executable).TrimEnd(Path.DirectorySeparatorChar);
            var package = Path.GetFullPath(packageRoot).TrimEnd(Path.DirectorySeparatorChar);
            var approved = Path.GetFullPath(approvedWindowsAppsRoot).TrimEnd(Path.DirectorySeparatorChar);
            if (!full.Equals(executable.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase) || !package.Equals(packageRoot.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase)) return false;
            if (!Path.GetFileName(full).Equals("winget.exe", StringComparison.OrdinalIgnoreCase)) return false;
            if (!Path.GetDirectoryName(full)!.Equals(package, StringComparison.OrdinalIgnoreCase)) return false;
            if (!Path.GetDirectoryName(package)!.Equals(approved, StringComparison.OrdinalIgnoreCase)) return false;
            var basename = Path.GetFileName(package);
            const string prefix = "Microsoft.DesktopAppInstaller_";
            const string suffix = "_x64__8wekyb3d8bbwe";
            if (!basename.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || !basename.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) return false;
            var version = basename[prefix.Length..^suffix.Length];
            if (string.IsNullOrWhiteSpace(version) || version.Split('.').Any(part => part.Length == 0 || !part.All(char.IsDigit))) return false;
            var packageInfo = new DirectoryInfo(package);
            var approvedInfo = new DirectoryInfo(approved);
            if (!packageInfo.Exists || !approvedInfo.Exists || packageInfo.Attributes.HasFlag(FileAttributes.ReparsePoint) || approvedInfo.Attributes.HasFlag(FileAttributes.ReparsePoint)) return false;
            if (!File.Exists(full) || (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) return false;
            return true;
        }
        catch { return false; }
    }

    public static bool IsUnderOwnedRoot(string candidate, string root)
    {
        try
        {
            var full = Path.GetFullPath(candidate);
            if (File.Exists(full) && (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) return false;
            var ownedRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!full.StartsWith(ownedRoot, StringComparison.OrdinalIgnoreCase)) return false;
            var current = new DirectoryInfo(Path.GetDirectoryName(full)!);
            var rootInfo = new DirectoryInfo(root);
            if (rootInfo.Attributes.HasFlag(FileAttributes.ReparsePoint)) return false;
            while (current is not null)
            {
                if (current.Attributes.HasFlag(FileAttributes.ReparsePoint)) return false;
                if (current.FullName.TrimEnd(Path.DirectorySeparatorChar).Equals(rootInfo.FullName.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase)) return true;
                current = current.Parent;
            }
        }
        catch { }
        return false;
    }

    public static void ValidateLedger(InstallLedger ledger)
    {
        foreach (var file in ledger.FilesInstalled.Where(x => !string.IsNullOrWhiteSpace(x)))
            if (!IsUnderOwnedRoot(file, AppPaths.InstallRoot)) throw new InvalidDataException($"Ledger path is outside the canonical DevFleet install root: {file}");
        foreach (var resource in ledger.OwnedResources.Where(x => !string.IsNullOrWhiteSpace(x.Path)))
            if (!IsUnderOwnedRoot(resource.Path, AppPaths.InstallRoot) && !IsUnderOwnedRoot(resource.Path, AppPaths.StateRoot)) throw new InvalidDataException($"Ledger resource path is outside canonical DevFleet roots: {resource.Path}");
        const string uninstall = @"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\DevFleet";
        if (ledger.RegistryEntriesCreated.Any(x => !x.Equals(uninstall, StringComparison.OrdinalIgnoreCase))) throw new InvalidDataException("Ledger contains an unapproved registry deletion target.");
        if (ledger.WindowsIntegrations.Count > 0)
        {
            var expected = Path.GetFullPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DevFleetHostAgent", "integration-ownership.json"));
            if (string.IsNullOrWhiteSpace(ledger.WindowsIntegrationOwnershipPath) || !Path.GetFullPath(ledger.WindowsIntegrationOwnershipPath).Equals(expected, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Windows integration ownership ledger path is not canonical.");
            if (!Guid.TryParse(ledger.InstallationGeneration, out var generation) || generation == Guid.Empty) throw new InvalidDataException("Windows integration generation is invalid.");
            if (ledger.WindowsIntegrations.Any(x => x.Generation != ledger.InstallationGeneration || string.IsNullOrWhiteSpace(x.Name) || x.Name.Contains('*') || x.Name.Contains('?'))) throw new InvalidDataException("Windows integration ledger contains an ambiguous or cross-generation identity.");
            if (ledger.WindowsIntegrations.GroupBy(x => $"{x.Kind}\0{x.Name}", StringComparer.OrdinalIgnoreCase).Any(group => group.Count() != 1)) throw new InvalidDataException("Windows integration ledger contains a duplicate identity.");
            foreach (var integration in ledger.WindowsIntegrations)
            {
                var complete = integration.Kind switch
                {
                    "ScheduledTask" => new[] { integration.Marker, integration.Executable, integration.Arguments, integration.Principal, integration.LogonType, integration.RunLevel, integration.Description }.All(x => !string.IsNullOrWhiteSpace(x)),
                    "FirewallRule" => new[] { integration.Marker, integration.DisplayName, integration.Group, integration.Description, integration.Direction, integration.Action, integration.Protocol, integration.LocalPort, integration.InterfaceAlias, integration.RemoteAddress, integration.Profile }.All(x => !string.IsNullOrWhiteSpace(x)),
                    "Service" => new[] { integration.Marker, integration.ImagePath, integration.Account, integration.StartMode }.All(x => !string.IsNullOrWhiteSpace(x)),
                    _ => false
                };
                if (!complete) throw new InvalidDataException($"Windows integration ledger contains an incomplete {integration.Kind} ownership binding.");
            }
        }
    }

    public static void ValidateCanonicalStateRoot()
    {
        if (!OperatingSystem.IsWindows()) return;
        foreach (var root in new[] { AppPaths.StateRoot, AppPaths.InstallerRoot })
        {
            if (!Directory.Exists(root)) continue;
            var info = new DirectoryInfo(root);
            if (info.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new InvalidDataException($"Canonical DevFleet state root is a reparse point: {root}");
            var security = info.GetAccessControl();
            foreach (var rule in security.GetAccessRules(true, true, typeof(NTAccount)))
            {
                if (rule is not FileSystemAccessRule access || access.AccessControlType != AccessControlType.Allow) continue;
                var identity = access.IdentityReference.Value;
                if (IsBroadUntrustedPrincipal(identity) && HasPrimitiveMutationRights(access.FileSystemRights)) throw new InvalidDataException($"Canonical DevFleet state root is writable by an untrusted identity: {root} ({identity}).");
            }
        }
    }
}

public static class SecureStagingService
{
    internal static DirectorySecurity BuildDirectorySecurity(string path)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new FileSystemAccessRule("BUILTIN\\Administrators", FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule("NT AUTHORITY\\SYSTEM", FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        if (TestEnvironment.IsAuthorizedSelfTestPath(path))
        {
            var currentSid = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("The self-test caller has no Windows SID.");
            security.AddAccessRule(new FileSystemAccessRule(currentSid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        }
        return security;
    }

    public static void EnsureDirectory(string path)
    {
        Directory.CreateDirectory(path);
        var info = new DirectoryInfo(path);
        if (info.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new InvalidDataException($"Refusing a reparse-point staging directory: {path}");
        if (!OperatingSystem.IsWindows()) return;
        info.SetAccessControl(BuildDirectorySecurity(path));
    }
}

public sealed record OwnedResource(string Kind, string Identity, string OwnerProof, string Path = "", string ProjectId = "");
public sealed record OwnedWindowsIntegration(
    string Kind,
    string Name,
    string Generation,
    string Marker,
    string Executable = "",
    string Arguments = "",
    string Principal = "",
    string LogonType = "",
    string RunLevel = "",
    string Description = "",
    string DisplayName = "",
    string Group = "",
    string Direction = "",
    string Action = "",
    string Protocol = "",
    string LocalPort = "",
    string InterfaceAlias = "",
    string RemoteAddress = "",
    string Profile = "",
    string ImagePath = "",
    string Account = "",
    string StartMode = "");

public static class StateStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static InstallLedger ReadLedger()
    {
        if (!File.Exists(AppPaths.LedgerPath)) return new InstallLedger();
        OwnedPathSafety.ValidateCanonicalStateRoot();
        var ledger = JsonSerializer.Deserialize<InstallLedger>(File.ReadAllText(AppPaths.LedgerPath), JsonOptions)
            ?? throw new InvalidDataException("DevFleet installation ledger is empty.");
        OwnedPathSafety.ValidateLedger(ledger);
        return ledger;
    }

    public static void WriteLedger(InstallLedger ledger)
    {
        if (!TestEnvironment.IsTestProcess) SecureStagingService.EnsureDirectory(AppPaths.StateRoot);
        Directory.CreateDirectory(AppPaths.InstallerRoot);
        if (!TestEnvironment.IsTestProcess) SecureStagingService.EnsureDirectory(AppPaths.InstallerRoot);
        WriteJsonAtomically(AppPaths.LedgerPath, ledger);
    }

    public static void WriteJsonAtomically<T>(string path, T value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temp, path, true);
            using (var committed = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read, 4096, FileOptions.WriteThrough))
                committed.Flush(flushToDisk: true);
            if (!File.ReadAllBytes(path).AsSpan().SequenceEqual(bytes))
                throw new IOException("The committed JSON state did not match the durably flushed bytes.");
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }
    }
}

public static class HashService
{
    public static string Sha256(Stream stream)
    {
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
    }

    public static string Sha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Sha256(stream);
    }
}

public static class PayloadService
{
    private static Stream OpenPayload()
    {
        var assembly = typeof(PayloadService).Assembly;
        var resource = assembly.GetManifestResourceNames().Single(n => n.EndsWith(PayloadManifest.PayloadName, StringComparison.OrdinalIgnoreCase));
        return assembly.GetManifestResourceStream(resource) ?? throw new InvalidOperationException("Embedded DevFleet payload is unavailable.");
    }

    public static string StageVerifiedPayload(string transactionId, Action<string>? progress = null)
    {
        SecureStagingService.EnsureDirectory(AppPaths.CacheRoot);
        var directory = Path.Combine(AppPaths.CacheRoot, PayloadManifest.DevFleetVersion, transactionId);
        SecureStagingService.EnsureDirectory(directory);
        var path = Path.Combine(directory, PayloadManifest.PayloadName);
        using (var payload = OpenPayload())
        {
            var hash = HashService.Sha256(payload);
            if (!hash.Equals(PayloadManifest.PayloadSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"Embedded payload hash mismatch: {hash}");
        }
        if (File.Exists(path))
        {
            if (!HashService.Sha256(path).Equals(PayloadManifest.PayloadSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("An existing staged payload failed the candidate hash check.");
            progress?.Invoke($"Payload verified from the existing reboot-resume staging path: {PayloadManifest.PayloadSha256}");
            return path;
        }
        try
        {
            using var input = OpenPayload();
            using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024, FileOptions.WriteThrough);
            input.CopyTo(output);
        }
        catch (IOException) when (File.Exists(path))
        {
            // Another same-candidate resume may have completed staging first;
            // verify that exact artifact instead of overwriting it.
        }
        if (!File.Exists(path) || !HashService.Sha256(path).Equals(PayloadManifest.PayloadSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Staged payload hash verification failed.");
        progress?.Invoke($"Payload verified: {PayloadManifest.PayloadSha256}");
        return path;
    }

    public static string ExtractVerifiedPayload(string stagedPath, string transactionId, Action<string>? progress = null)
    {
        if (!HashService.Sha256(stagedPath).Equals(PayloadManifest.PayloadSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Refusing to extract an unverified payload.");
        var destination = Path.Combine(AppPaths.InstallRoot, "Release", PayloadManifest.DevFleetVersion);
        Directory.CreateDirectory(destination);
        using var input = File.OpenRead(stagedPath);
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        TarFile.ExtractToDirectory(gzip, destination, true);
        progress?.Invoke($"Release extracted to the owned install root for transaction {transactionId}.");
        return destination;
    }
}

public static class PreflightService
{
    public static PreflightReport Run()
    {
        var virtualization = Probe("(Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).HypervisorPresent; (Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1).VirtualizationFirmwareEnabled");
        var hostAgentScript = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DevFleetHostAgent", "DevFleet-HostAgent.ps1");
        var hostAgent = File.Exists(hostAgentScript) ? Probe($"& '{hostAgentScript.Replace("'", "''")}' -ValidateOnly") : "Not detected";
        var multipass = Probe("multipass version; multipass list --format json");
        var projects = new ProjectDiscoveryService().Discover();
        var backupCount = projects.Select(new BackupVerificationService().Verify).Count(x => x.IsVerified);
        var report = new PreflightReport
        {
            Administrator = OperatingSystem.IsWindows() && new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator),
            VirtualizationLikelyAvailable = virtualization.Contains("True", StringComparison.OrdinalIgnoreCase),
            PendingReboot = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") is not null,
            RamBytes = (ulong)Math.Max(0, GC.GetGCMemoryInfo().TotalAvailableMemoryBytes),
            FreeDiskBytes = new DriveInfo(Path.GetPathRoot(AppPaths.StateRoot) ?? "C:\\").AvailableFreeSpace,
            ExistingDevFleetVersion = ReadExistingVersion(),
            HostAgentVersion = hostAgent,
            MultipassState = string.IsNullOrWhiteSpace(multipass) ? "Not detected" : multipass.Trim(),
            DetectedRole = File.Exists(AppPaths.LedgerPath) ? StateStore.ReadLedger().Role : "Standalone / unknown",
            ProjectCount = projects.Count,
            BackupCount = backupCount
        };
        if (!report.Administrator) report.Warnings.Add("The current process is not elevated; machine-wide installation may require elevation.");
        if (!report.VirtualizationLikelyAvailable) report.Warnings.Add("Hardware virtualization could not be positively detected.");
        if (report.PendingReboot) report.Warnings.Add("Windows reports a pending reboot. Setup will not reboot automatically.");
        if (report.FreeDiskBytes < 2L * 1024 * 1024 * 1024) report.Blockers.Add("Less than 2 GiB of free disk space is available.");
        return report;
    }

    private static string Probe(string command)
    {
        try
        {
            var shell = TestEnvironment.IsTestProcess && !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("DEVFLEET_POWERSHELL_PATH"))
                ? Environment.GetEnvironmentVariable("DEVFLEET_POWERSHELL_PATH")!
                : TrustedExecutableResolver.PowerShellPath();
            using var process = Process.Start(new ProcessStartInfo { FileName = shell, ArgumentList = { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command }, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true });
            if (process is null) return "Not detected";
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try
            {
                process.WaitForExitAsync(timeout.Token).GetAwaiter().GetResult();
                var exitCode = process.ExitCode;
                var outputComplete = Task.WhenAll(stdout, stderr).Wait(TimeSpan.FromSeconds(1));
                if (!outputComplete) return $"Probe process exited {exitCode}, but redirected output was incomplete after the bounded post-exit drain.";
                var output = string.Join(Environment.NewLine, stdout.Result, stderr.Result).Trim();
                return output[..Math.Min(16000, output.Length)];
            }
            catch (OperationCanceledException)
            {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
                Task.WaitAll([stdout, stderr], TimeSpan.FromSeconds(1));
                return "Probe timed out after 5 seconds.";
            }
        }
        catch { return "Not detected"; }
    }

    private static string ReadExistingVersion()
    {
        try { return File.Exists(AppPaths.LedgerPath) ? StateStore.ReadLedger().DevFleetVersion : "Not detected"; }
        catch { return "Unknown"; }
    }

    public static string ToText(PreflightReport report) => $"""
DevFleet Setup preflight (read-only)
Timestamp UTC: {report.TimestampUtc}
Windows: {report.WindowsVersion}
Architecture: {report.Architecture}
Administrator: {report.Administrator}
Virtualization likely available: {report.VirtualizationLikelyAvailable}
Pending reboot: {report.PendingReboot}
RAM bytes: {report.RamBytes}
Free disk bytes: {report.FreeDiskBytes}
Existing DevFleet: {report.ExistingDevFleetVersion}
Host Agent: {report.HostAgentVersion}
Multipass: {report.MultipassState}
Detected role: {report.DetectedRole}
Projects: {report.ProjectCount}
Backups: {report.BackupCount}
Blockers: {string.Join("; ", report.Blockers)}
Warnings: {string.Join("; ", report.Warnings)}
""";
}

public static class PlanService
{
    public static InstallerPlan Build(InstallerMode mode, bool preserveProjects, bool preserveBackups, bool removePrerequisites, bool projectDataSelected, bool verifiedBackup, string controlPhrase, string projectPhrase, IReadOnlyCollection<string>? selectedProjectIds = null, bool deferNetworkPairing = false, bool acknowledgeRootfulDocker = false)
    {
        var plan = new InstallerPlan { Mode = mode, PreserveProjects = preserveProjects, PreserveBackups = preserveBackups, RemovePrerequisites = removePrerequisites, ProjectDataSelected = projectDataSelected, VerifiedBackup = verifiedBackup, DeferNetworkPairing = deferNetworkPairing, AcknowledgeRootfulDocker = acknowledgeRootfulDocker };
        var ledger = StateStore.ReadLedger();
        if (mode is InstallerMode.FreshInstall or InstallerMode.Repair or InstallerMode.CleanReinstall or InstallerMode.LocalUpdate)
            plan.Items.Add(new PlanItem(AppPaths.InstallRoot, mode == InstallerMode.Repair ? "Verify and restore owned application files" : "Stage, verify, and install the canonical release", true, mode == InstallerMode.CleanReinstall, "Restore the prior ledger and recovery package."));
        if (mode is InstallerMode.CleanReinstall or InstallerMode.Uninstall or InstallerMode.FactoryReset)
            plan.Items.Add(new PlanItem(AppPaths.InstallRoot, "Remove only ledger-listed DevFleet files", ledger.FilesInstalled.Count > 0, true, "Reinstall from the verified payload or recovery package."));
        if (mode == InstallerMode.FactoryReset && projectDataSelected)
        {
            if (!verifiedBackup) plan.Items.Add(new PlanItem("Selected project restore points", "Historical backups are informational only; Factory Reset will create a fresh safety backup immediately before deletion", true, false, "Restore from a labeled historical restore point."));
            var requested = (selectedProjectIds ?? []).Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).ToArray();
            var ids = requested.ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (ids.Count != requested.Length) plan.Blockers.Add("Factory Reset selection contains duplicate project IDs; review the exact selection again.");
            var allDiscovered = new ProjectDiscoveryService().Discover();
            var discovered = allDiscovered.Where(x => ids.Contains(x.ProjectId)).ToArray();
            var rediscoveredIds = discovered.Select(x => x.ProjectId).ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (!rediscoveredIds.SetEquals(ids)) plan.Blockers.Add("Factory Reset selection drifted: the reviewed project ID set no longer exists exactly.");
            foreach (var project in discovered) plan.SelectedProjects.Add(project);
            foreach (var id in ids) plan.SelectedProjectIds.Add(id);
            if (discovered.Length == 0) plan.Blockers.Add("Project-data deletion is blocked until at least one individual project is selected.");
            foreach (var project in discovered)
            {
                if (!project.OwnershipStatus.Equals("VERIFIED", StringComparison.OrdinalIgnoreCase)) plan.Blockers.Add($"Project {project.Slug} is {project.OwnershipStatus} ({project.AmbiguityReason}); only structurally VERIFIED projects may be selected.");
                plan.Items.Add(new PlanItem($"{project.Slug} ({project.RuntimeId})", "Quiesce, create a fresh transaction-specific safety backup, verify it, then invoke exact Host Agent destroy", true, true, "Restore the selected project from a labeled historical restore point."));
            }
            if (controlPhrase != "DELETE DEVFLEET") plan.Blockers.Add("Type DELETE DEVFLEET exactly to authorize control-plane removal.");
            if (projectPhrase != "DELETE DEVFLEET PROJECT DATA") plan.Blockers.Add("Type DELETE DEVFLEET PROJECT DATA exactly to authorize project-data removal.");
        }
        else if (mode == InstallerMode.FactoryReset && controlPhrase != "DELETE DEVFLEET")
            plan.Blockers.Add("Type DELETE DEVFLEET exactly to authorize the selected factory-reset scope.");
        if (removePrerequisites && ledger.PrerequisitesInstalledByDevFleet.Count == 0)
            plan.Blockers.Add("Shared prerequisites cannot be removed because the ownership ledger has no DevFleet-installed prerequisite proof.");
        if (mode == InstallerMode.CleanReinstall && !preserveProjects) plan.Blockers.Add("Clean Reinstall must preserve projects by default; select Factory Reset for project-data removal.");
        return plan;
    }

    public static string ToText(InstallerPlan plan) => string.Join(Environment.NewLine, [
        $"Transaction: {plan.TransactionId}", $"Mode: {plan.Mode}", $"Preserve projects: {plan.PreserveProjects}", $"Preserve backups: {plan.PreserveBackups}", $"Defer network pairing: {plan.DeferNetworkPairing}", $"Rootful Docker acknowledged: {plan.AcknowledgeRootfulDocker}", $"Project data selected: {plan.ProjectDataSelected}", $"Verified backup: {plan.VerifiedBackup}",
        "Plan:", .. plan.Items.Select(i => $"  {(i.Destructive ? "[destructive]" : "[safe]")} {i.Action} -> {i.Target} (owned={i.Owned})"),
        "Blockers:", .. plan.Blockers.Select(b => "  " + b)
    ]);
}

public static class RecoveryService
{
    public static string Create(string transactionId, Action<string>? progress = null)
    {
        var directory = Path.Combine(AppPaths.StateRoot, "Recovery"); Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"DevFleet-Recovery-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{transactionId[..8]}.zip");
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        var manifest = new { createdUtc = DateTime.UtcNow.ToString("O"), transactionId, devFleetVersion = PayloadManifest.DevFleetVersion, packageSha256 = PayloadManifest.PayloadSha256, includesSecrets = false, notes = "Recovery metadata only; raw reusable private secrets are excluded." };
        AddText(zip, "recovery-manifest.json", JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }));
        AddText(zip, "install-state.json", JsonSerializer.Serialize(StateStore.ReadLedger(), new JsonSerializerOptions { WriteIndented = true }));
        AddText(zip, "project-inventory.json", JsonSerializer.Serialize(new ProjectDiscoveryService().Discover(), new JsonSerializerOptions { WriteIndented = true }));
        AddText(zip, "runtime-inventory.json", JsonSerializer.Serialize(new { provider = "Multipass", note = "Runtime inventory is identity-only; no VM is deleted by recovery creation." }, new JsonSerializerOptions { WriteIndented = true }));
        AddText(zip, "backup-catalog.json", JsonSerializer.Serialize(new { verifiedUtc = DateTime.UtcNow.ToString("O"), backups = new ProjectDiscoveryService().Discover().Select(new BackupVerificationService().Verify).Select(x => new { x.ProjectId, x.BackupId, x.ArchivePath, x.ExpectedSha256, x.RestoreEligible, x.IsVerified }) }, new JsonSerializerOptions { WriteIndented = true }));
        AddText(zip, "dependency-inventory.json", JsonSerializer.Serialize(new { offlinePayload = false, note = "Third-party prerequisite installers are not bundled in this candidate." }, new JsonSerializerOptions { WriteIndented = true }));
        AddText(zip, "managed-integrations.json", JsonSerializer.Serialize(new { ssh = "managed blocks listed by ledger/source", vscode = "managed aliases listed by ledger/source", services = "DevFleet-owned service/task inventory required before removal", firewall = "exact DevFleet-owned rule inventory required before removal" }, new JsonSerializerOptions { WriteIndented = true }));
        AddText(zip, "recovery-instructions.txt", "Restore only to an explicitly selected DevFleet-owned destination after verifying identity and hashes. This package intentionally excludes raw private keys, tokens, passwords, and reusable credentials.\n");
        progress?.Invoke($"Recovery package created: {path}");
        return path;
    }

    private static void AddText(ZipArchive zip, string name, string value)
    {
        using var writer = new StreamWriter(zip.CreateEntry(name).Open()); writer.Write(value);
    }
}

public static class ControlPlaneSnapshotService
{
    public static string Capture(string transactionId, Action<string>? progress = null)
    {
        var source = AppPaths.InstallRoot;
        var target = Path.Combine(AppPaths.StateRoot, "Recovery", $"control-plane-{transactionId}");
        if (Directory.Exists(target)) Directory.Delete(target, true);
        if (Directory.Exists(source)) CopyDirectory(source, target);
        progress?.Invoke($"Transactional control-plane snapshot captured: {target}");
        return target;
    }

    public static void Restore(string snapshot, Action<string>? progress = null)
    {
        if (!Directory.Exists(snapshot)) throw new DirectoryNotFoundException($"Control-plane rollback snapshot is missing: {snapshot}");
        if (Directory.Exists(AppPaths.InstallRoot)) Directory.Delete(AppPaths.InstallRoot, true);
        CopyDirectory(snapshot, AppPaths.InstallRoot);
        progress?.Invoke("Transactional control-plane snapshot restored after failed replacement.");
    }

    public static void Delete(string snapshot)
    {
        if (Directory.Exists(snapshot)) Directory.Delete(snapshot, true);
    }

    private static void CopyDirectory(string source, string target)
    {
        Directory.CreateDirectory(target);
        foreach (var file in Directory.EnumerateFiles(source)) File.Copy(file, Path.Combine(target, Path.GetFileName(file)), true);
        foreach (var directory in Directory.EnumerateDirectories(source)) CopyDirectory(directory, Path.Combine(target, Path.GetFileName(directory)));
    }
}

public sealed class InstallerLogger
{
    private readonly string _path = Path.Combine(AppPaths.LogsRoot, $"setup-{DateTime.UtcNow:yyyyMMdd-HHmmss}.log");
    public string LogPath => _path;
    public InstallerLogger() => Directory.CreateDirectory(AppPaths.LogsRoot);
    public void Write(string message)
    {
        var safe = message.Replace("Bearer ", "Bearer [REDACTED]", StringComparison.OrdinalIgnoreCase);
        File.AppendAllText(_path, $"{DateTime.UtcNow:O} {safe}{Environment.NewLine}");
    }
}

public static class InstallerEngine
{
    public static string Execute(InstallerPlan plan, string role, Action<string>? progress = null) => LifecycleEngine.Execute(plan, role, progress);

    internal static void RemoveLedgerFiles(InstallLedger ledger, Action<string>? progress)
    {
        var root = Path.GetFullPath(AppPaths.InstallRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        foreach (var file in ledger.FilesInstalled.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var full = Path.GetFullPath(file);
            if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase) || !File.Exists(full)) continue;
            File.Delete(full);
            if (File.Exists(full)) throw new IOException($"Owned file remains after cleanup: {full}");
            progress?.Invoke($"Removed and verified owned file: {full}");
        }
    }

    private static void RemoveOwnedProjectResources(InstallLedger ledger, Action<string>? progress)
    {
        foreach (var resource in ledger.OwnedResources.Where(r => !string.IsNullOrWhiteSpace(r.ProjectId) && r.OwnerProof.Equals("DevFleetLedger", StringComparison.OrdinalIgnoreCase)))
        {
            if (string.IsNullOrWhiteSpace(resource.Path)) { progress?.Invoke($"Manual review required: owned project resource {resource.Identity} has no path."); continue; }
            var full = Path.GetFullPath(resource.Path);
            var root = Path.GetPathRoot(full);
            if (string.IsNullOrWhiteSpace(root) || full.TrimEnd(Path.DirectorySeparatorChar).Equals(root.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase) || full.TrimEnd(Path.DirectorySeparatorChar).Equals(Path.GetFullPath(AppPaths.StateRoot).TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
            {
                progress?.Invoke($"Manual review required: refusing broad project target {full}.");
                continue;
            }
            if (Directory.Exists(full)) Directory.Delete(full, true);
            else if (File.Exists(full)) File.Delete(full);
            progress?.Invoke($"Removed independently proven owned project resource: {resource.Identity} ({full})");
        }
    }

    private static void CreateInstalledAppEntry(InstallLedger ledger)
    {
        using var key = Registry.LocalMachine.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\DevFleet");
        if (key is null) return;
        var exe = ledger.FilesInstalled.FirstOrDefault(p => Path.GetFileName(p).Equals("DevFleet.Setup.exe", StringComparison.OrdinalIgnoreCase)) ?? Environment.ProcessPath ?? "DevFleet.Setup.exe";
        key.SetValue("DisplayName", "DevFleet"); key.SetValue("Publisher", "M-TechLabs"); key.SetValue("DisplayVersion", PayloadManifest.DevFleetVersion); key.SetValue("InstallLocation", AppPaths.InstallRoot); key.SetValue("UninstallString", $"\"{exe}\" --maintenance --action uninstall");
        ledger.RegistryEntriesCreated.Add(@"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\DevFleet");
    }

    private static void InstallStableLauncher(InstallLedger ledger, Action<string>? progress)
    {
        var current = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(current) || !File.Exists(current)) return;
        Directory.CreateDirectory(AppPaths.InstallRoot);
        var target = Path.Combine(AppPaths.InstallRoot, "DevFleet.Setup.exe");
        if (!Path.GetFullPath(current).Equals(Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase)) File.Copy(current, target, true);
        ledger.FilesInstalled.Add(target); ledger.OwnedResources.Add(new OwnedResource("launcher", "DevFleet Setup", "DevFleetLedger", target)); progress?.Invoke($"Stable installed launcher recorded: {target}");
    }

    private static void CreateShortcuts(InstallLedger ledger, Action<string>? progress)
    {
        var exe = Environment.ProcessPath; if (string.IsNullOrWhiteSpace(exe)) return;
        var start = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs", "DevFleet"); Directory.CreateDirectory(start);
        foreach (var item in new[] { ("DevFleet", "--maintenance"), ("DevFleet Maintenance", "--maintenance") })
        {
            var path = Path.Combine(start, item.Item1 + ".lnk");
            try
            {
                var type = Type.GetTypeFromProgID("WScript.Shell"); if (type is null) continue;
                dynamic shell = Activator.CreateInstance(type)!; dynamic shortcut = shell.CreateShortcut(path); shortcut.TargetPath = exe; shortcut.Arguments = item.Item2; shortcut.WorkingDirectory = Path.GetDirectoryName(exe); shortcut.Description = "DevFleet maintenance and workspace tools"; shortcut.Save(); ledger.ShortcutsCreated.Add(path); progress?.Invoke($"Shortcut created: {path}");
            }
            catch { progress?.Invoke($"Shortcut creation unavailable; the stable maintenance entry remains available from Installed Apps."); }
        }
    }
}
