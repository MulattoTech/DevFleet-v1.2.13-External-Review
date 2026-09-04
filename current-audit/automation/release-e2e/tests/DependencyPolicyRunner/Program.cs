using System.Net;
using System.Net.Http;
using DevFleet.Setup;
using DependencyPolicyRunner;

if (args.Contains("--runner-self-test", StringComparer.OrdinalIgnoreCase))
{
    RunRunnerSelfTest();
    return;
}

static object Row(string scenario, string branch, bool reached, ArgumentAwareProcessRunner runner, string? selectedFallback = null, string? detail = null, bool physicalPathExists = false)
    => new {
        scenario,
        requestedScenario = scenario,
        actualResolverBranch = branch,
        queuedProcessOutputs = runner.Invocations.Select(i => new { i.FileName, arguments = i.Arguments, intendedProbe = i.IntendedProbe.ToString(), result = i.Result }).ToArray(),
        actualInvocations = runner.Invocations.Count,
        selectedFallback,
        detectedVersionOrPath = detail,
        physicalPathExists,
        authenticityProbeReached = runner.Invocations.Any(i => i.IntendedProbe == ProcessProbe.Authenticode),
        versionProbeReached = runner.Invocations.Any(i => i.IntendedProbe is ProcessProbe.Version or ProcessProbe.WingetVersion),
        trustedPathPolicyReached = runner.Invocations.Count > 0,
        expectedOutcome = "policy branch exercised and fails closed on mismatch",
        actualOutcome = reached ? "intended branch reached" : "intended branch not reached",
        actualConditionProven = reached,
        status = reached ? "PASS" : "FAIL",
        evidenceClass = "ADVERSARIAL_PRODUCT_POLICY"
    };

var rows = new List<object>();

// Missing WinGet is a real resolver call with a process-scoped empty PATH.
var originalPath = Environment.GetEnvironmentVariable("PATH");
try
{
    Environment.SetEnvironmentVariable("PATH", "");
    var missingRunner = new ArgumentAwareProcessRunner();
    var missing = new DependencyService(missingRunner).GetWingetHealth();
    rows.Add(Row("WinGet-Missing", missing.Status, missing.Status == "Missing", missingRunner, detail: missing.Detail));
}
finally { Environment.SetEnvironmentVariable("PATH", originalPath); }

// These cases use the real dependency resolver with argument-aware fixtures.
// The AppX and Authenticode probes are keyed separately from the WinGet
// operation, so they cannot consume --version/source/search results.
foreach (var (scenario, expected) in new[] {
    ("WinGet-Broken", "Broken"),
    ("WinGet-Source-Broken", "SourceBroken")
})
{
    var runner = new ArgumentAwareProcessRunner();
    var physicalWinget = LocatePhysicalWingetPackage();
    ConfigureWingetFixtures(runner, scenario);
    var health = new DependencyService(runner).GetWingetHealth();
    rows.Add(Row(scenario, health.Status, health.Status.Equals(expected, StringComparison.OrdinalIgnoreCase), runner, detail: health.Detail, physicalPathExists: File.Exists(physicalWinget.Executable)));
}

// Official direct fallback is exercised with the real HttpClient injection,
// using an allowlisted synthetic metadata response and no machine mutation.
var fallbackRunner = new ArgumentAwareProcessRunner();
var handler = new StubHandler();
using var http = new HttpClient(handler);
var dependency = new DependencyDefinition {
    Id = "fixture-direct",
    DisplayName = "Fixture Direct",
    DirectOfficialVendorResolver = new OfficialResolver {
        Type = "official-download-page",
        MetadataUri = "https://downloads.example.invalid/release.json",
        DirectUri = "https://downloads.example.invalid/fixture.exe",
        AllowedHosts = ["downloads.example.invalid"],
        AssetRegex = "^fixture\\.exe$"
    }
};
var fallbackRoot = Path.Combine(Path.GetTempPath(), "devfleet-policy-runner-" + Guid.NewGuid().ToString("N"));
var fallbackPath = new DependencyService(fallbackRunner, http).DownloadOfficial(dependency, fallbackRoot);
var fallbackReached = File.Exists(fallbackPath) && string.Equals(Path.GetFileName(fallbackPath), "fixture.exe", StringComparison.OrdinalIgnoreCase);
rows.Add(Row("Official-Direct-Fallback", "DirectOfficialFallback", fallbackReached, fallbackRunner, selectedFallback: fallbackPath, detail: handler.LastUri));
try { Directory.Delete(fallbackRoot, recursive: true); } catch { }

// Nonstandard-path detection selects only a physically existing executable
// from real machine roots.  The selection is deliberately not a temp fixture:
// Detect() remains the authority for the unmodified shipping trust policy.
var nonstandardRunner = new ArgumentAwareProcessRunner();
var trustedFixtureCandidates = new[] {
    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "PowerShell", "7", "pwsh.exe"),
    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "where.exe"),
    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}.Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
var trustedFixturePath = trustedFixtureCandidates.FirstOrDefault();
if (trustedFixturePath is null) {
    rows.Add(Row("Valid-Nonstandard-Path", "TrustedDiscoveryCompatible", false, nonstandardRunner, detail: "No physically existing executable was available in a real trusted-root candidate set.", physicalPathExists: false));
    rows.Add(Row("Outdated-Prerequisites", "OutdatedVersion", false, nonstandardRunner, detail: "No physically existing executable was available in a real trusted-root candidate set.", physicalPathExists: false));
    goto Emit;
}
QueueAuthenticodeFixture(nonstandardRunner, trustedFixturePath, new ProcessResult(1, "", "unsigned fixture is accepted by the explicit test policy"));
nonstandardRunner.QueueResult(trustedFixturePath, ["--version"], new ProcessResult(0, "7.4.0", ""));
var nonstandard = new DependencyService(nonstandardRunner).Detect(new DependencyDefinition {
    Id = "fixture-path", DisplayName = "Fixture Path", KnownVendorInstallLocations = [trustedFixturePath],
    MinimumSupportedVersion = "1.0.0", VersionProbe = new VersionProbe { Regex = "(\\d+\\.\\d+)" },
    InstallerAuthenticityPolicy = new InstallerAuthenticityPolicy { InstalledExecutableTrust = "signed-installer-locked-path" }
});
var nonstandardReached = nonstandard.Found && nonstandard.Version is not null && nonstandard.Compatible
    && string.Equals(nonstandard.ExecutablePath, trustedFixturePath, StringComparison.OrdinalIgnoreCase)
    && nonstandardRunner.Invocations.Count >= 2;
rows.Add(Row("Valid-Nonstandard-Path", "TrustedDiscoveryCompatible", nonstandardReached, nonstandardRunner, detail: $"{nonstandard.ExecutablePath}|version={nonstandard.Version}", physicalPathExists: File.Exists(trustedFixturePath)));

// Outdated prerequisites is represented by a real incompatible detection.
var outdatedRunner = new ArgumentAwareProcessRunner();
QueueAuthenticodeFixture(outdatedRunner, trustedFixturePath, new ProcessResult(1, "", "unsigned fixture is accepted by the explicit test policy"));
outdatedRunner.QueueResult(trustedFixturePath, ["--version"], new ProcessResult(0, "1.0.0", ""));
var outdated = new DependencyService(outdatedRunner).Detect(new DependencyDefinition {
    Id = "fixture-outdated", DisplayName = "Fixture Outdated", KnownVendorInstallLocations = [trustedFixturePath],
    MinimumSupportedVersion = "99.0.0", VersionProbe = new VersionProbe { Regex = "(\\d+\\.\\d+)" },
    InstallerAuthenticityPolicy = new InstallerAuthenticityPolicy { InstalledExecutableTrust = "signed-installer-locked-path" }
});
var outdatedReached = outdated.Found && outdated.Version is not null && outdated.Version < new Version("99.0.0")
    && !outdated.Compatible && outdated.Classification.Length > 0 && outdatedRunner.Invocations.Count >= 2;
rows.Add(Row("Outdated-Prerequisites", "OutdatedVersion", outdatedReached, outdatedRunner, detail: $"{outdated.ExecutablePath}|version={outdated.Version}|minimum=99.0.0", physicalPathExists: File.Exists(trustedFixturePath)));
Emit:
Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(rows));
var requiredScenarios = new[] { "WinGet-Missing", "WinGet-Broken", "WinGet-Source-Broken", "Official-Direct-Fallback", "Valid-Nonstandard-Path", "Outdated-Prerequisites" };
var actualScenarios = rows.Select(row => (string)row.GetType().GetProperty("scenario")!.GetValue(row)! ).ToArray();
if (actualScenarios.Length != requiredScenarios.Length || actualScenarios.Distinct(StringComparer.Ordinal).Count() != requiredScenarios.Length ||
    !requiredScenarios.All(id => actualScenarios.Contains(id, StringComparer.Ordinal)))
    Environment.ExitCode = 2;
if (rows.Any(row => !(bool)row.GetType().GetProperty("actualConditionProven")!.GetValue(row)!))
    Environment.ExitCode = 1;

static void ConfigureWingetFixtures(ArgumentAwareProcessRunner runner, string scenario)
{
    var (packageRoot, winget) = LocatePhysicalWingetPackage();
    var powershell = GetPowerShellPath();
    var appxArguments = new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Get-AppxPackage -AllUsers -Name 'Microsoft.DesktopAppInstaller' | ForEach-Object { Join-Path $_.InstallLocation 'winget.exe' }" };
    runner.QueueResult(powershell, appxArguments,
        new ProcessResult(0, winget, ""), ProcessProbe.AppxPackageTrust);
    var packageIdentityArguments = new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Get-AppxPackage -AllUsers -Name 'Microsoft.DesktopAppInstaller' | ForEach-Object { $_.Name + '|' + $_.PublisherId + '|' + $_.InstallLocation }" };
    runner.QueueResult(powershell, packageIdentityArguments,
        new ProcessResult(0, $"Microsoft.DesktopAppInstaller|8wekyb3d8bbwe|{packageRoot}", ""), ProcessProbe.AppxPackageTrust);
    QueueAuthenticodeFixture(runner, winget,
        new ProcessResult(0, "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US", ""));

    if (scenario.Equals("WinGet-Broken", StringComparison.OrdinalIgnoreCase))
    {
        runner.QueueResult(winget, ["--version"], new ProcessResult(1, "", "fixture winget failure"), ProcessProbe.WingetVersion);
        return;
    }

    runner.QueueResult(winget, ["--version"], new ProcessResult(0, "v1.9.0", ""), ProcessProbe.WingetVersion);
    runner.QueueResult(winget, ["source", "list", "--disable-interactivity"], new ProcessResult(1, "", "fixture source failure"), ProcessProbe.WingetSourceList);
}

static (string PackageRoot, string Executable) LocatePhysicalWingetPackage()
{
    if (!OperatingSystem.IsWindows()) throw new InvalidOperationException("The dependency matrix requires the Windows physical WinGet package.");
    var windowsApps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps");
    var matches = Directory.EnumerateDirectories(windowsApps, "Microsoft.DesktopAppInstaller_*_8wekyb3d8bbwe", SearchOption.TopDirectoryOnly)
        .Where(path => !new DirectoryInfo(path).Attributes.HasFlag(FileAttributes.ReparsePoint))
        .Select(path => (Root: path, Executable: Path.Combine(path, "winget.exe")))
        .Where(item => File.Exists(item.Executable) && !File.GetAttributes(item.Executable).HasFlag(FileAttributes.ReparsePoint))
        .ToArray();
    if (matches.Length != 1) throw new InvalidOperationException($"Expected exactly one physical Microsoft.DesktopAppInstaller package with winget.exe, found {matches.Length}.");
    return matches[0];
}

static void QueueAuthenticodeFixture(ArgumentAwareProcessRunner runner, string executable, ProcessResult result)
{
    var escaped = executable.Replace("'", "''", StringComparison.Ordinal);
    var command = "$s=Get-AuthenticodeSignature -LiteralPath '" + escaped + "'; if($s.Status -ne 'Valid'){exit 9}; $s.SignerCertificate.Subject";
    runner.QueueResult(GetPowerShellPath(),
        ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command], result, ProcessProbe.Authenticode);
}

static string GetPowerShellPath()
{
    var candidates = new[]
    {
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "PowerShell", "7", "pwsh.exe"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    };
    return candidates.FirstOrDefault(File.Exists) ?? "pwsh.exe";
}

static void RunRunnerSelfTest()
{
    var winget = @"C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\winget.exe";
    var runner = new ArgumentAwareProcessRunner();
    runner.QueueResult(winget, [" --version "], new ProcessResult(1, "", "exact version failure"), ProcessProbe.WingetVersion);
    runner.QueueResult(winget, ["source", "list", "--disable-interactivity"], new ProcessResult(0, "source-ok", ""), ProcessProbe.WingetSourceList);

    // Deliberately call source before version: keyed dispatch must preserve
    // each fixture's intended operation instead of consuming FIFO output.
    var source = runner.Run(winget, ["source", "list", "--disable-interactivity"]);
    var version = runner.Run(winget, ["--version"]);
    var unknown = runner.Run(winget, ["search", "--id", "fixture"]);
    if (source.ExitCode != 0 || source.StandardOutput != "source-ok" || source != runner.Invocations[0].Result ||
        version.ExitCode != 1 || version.StandardError != "exact version failure" || version != runner.Invocations[1].Result ||
        unknown.ExitCode != 127 || runner.Invocations.Count != 3 ||
        runner.Invocations[0].IntendedProbe != ProcessProbe.WingetSourceList ||
        runner.Invocations[1].IntendedProbe != ProcessProbe.WingetVersion ||
        runner.Invocations[2].IntendedProbe != ProcessProbe.WingetSearch)
        throw new InvalidOperationException("Argument-aware process runner self-test failed.");

    Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new
    {
        status = "PASS",
        contract = "executable+normalized-arguments+intended-probe",
        invocationOrder = runner.Invocations.Select(i => new { i.IntendedProbe, i.FileName, arguments = i.Arguments, result = i.Result }).ToArray(),
        missingFixture = new { unknown.ExitCode, unknown.StandardError }
    }));
}

sealed class StubHandler : HttpMessageHandler
{
    public string LastUri { get; private set; } = "";
    private HttpResponseMessage Build(HttpRequestMessage request)
    {
        LastUri = request.RequestUri?.ToString() ?? "";
        var content = request.RequestUri?.AbsolutePath.EndsWith("fixture.exe", StringComparison.OrdinalIgnoreCase) == true
            ? new ByteArrayContent([0x4d, 0x5a, 0x46, 0x49, 0x58, 0x54, 0x55, 0x52, 0x45])
            : new StringContent("{\"tag_name\":\"fixture\",\"assets\":[]}");
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
    }
    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken) => Build(request);
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        => Task.FromResult(Build(request));
}
