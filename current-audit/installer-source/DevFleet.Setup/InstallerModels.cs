using System.Collections.ObjectModel;

namespace DevFleet.Setup;

public enum InstallerMode
{
    Diagnostics,
    FreshInstall,
    Repair,
    CleanReinstall,
    Uninstall,
    FactoryReset,
    LocalUpdate,
    RecoveryPackage
}

public enum TransactionState
{
    Planned,
    InProgress,
    Completed,
    Failed,
    RollbackInProgress,
    RolledBack,
    RollbackIncomplete
}

public sealed record PlanItem(string Target, string Action, bool Owned, bool Destructive, string Rollback);

public sealed class InstallerPlan
{
    public string TransactionId { get; set; } = Guid.NewGuid().ToString("N");
    public InstallerMode Mode { get; init; }
    public bool PreserveProjects { get; init; } = true;
    public bool PreserveBackups { get; init; } = true;
    public bool RemovePrerequisites { get; init; }
    public bool ProjectDataSelected { get; init; }
    public bool VerifiedBackup { get; init; }
    public bool DeferNetworkPairing { get; init; }
    public bool AcknowledgeRootfulDocker { get; init; }
    public Collection<string> SelectedProjectIds { get; } = [];
    public Collection<DiscoveredProject> SelectedProjects { get; } = [];
    public Collection<PlanItem> Items { get; } = [];
    public Collection<string> Blockers { get; } = [];
    public bool IsMutation => Mode is not InstallerMode.Diagnostics and not InstallerMode.RecoveryPackage;
    public bool IsAllowed => Blockers.Count == 0;
}

public sealed class PreflightReport
{
    public string TimestampUtc { get; init; } = DateTime.UtcNow.ToString("O");
    public string WindowsVersion { get; init; } = Environment.OSVersion.VersionString;
    public string Architecture { get; init; } = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString();
    public bool Administrator { get; init; }
    public bool VirtualizationLikelyAvailable { get; init; }
    public bool PendingReboot { get; init; }
    public ulong RamBytes { get; init; }
    public long FreeDiskBytes { get; init; }
    public string ExistingDevFleetVersion { get; init; } = "Not detected";
    public string HostAgentVersion { get; init; } = "Not probed";
    public string MultipassState { get; init; } = "Not probed (diagnostics is read-only)";
    public string DetectedRole { get; init; } = "Standalone / unknown";
    public int ProjectCount { get; init; }
    public int BackupCount { get; init; }
    public Collection<string> Blockers { get; } = [];
    public Collection<string> Warnings { get; } = [];
}
