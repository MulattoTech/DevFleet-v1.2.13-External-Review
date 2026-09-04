using DevFleet.Setup;

namespace DependencyPolicyRunner;

public enum ProcessProbe
{
    Unknown,
    AppxPackageTrust,
    Authenticode,
    WingetVersion,
    WingetSourceList,
    WingetSearch,
    WingetDownload,
    Version,
    Other
}

public sealed record RecordedProcessInvocation(
    string FileName,
    IReadOnlyList<string> Arguments,
    string? WorkingDirectory,
    ProcessProbe IntendedProbe,
    ProcessResult Result);

internal sealed record FixtureKey(string Executable, string Arguments, ProcessProbe IntendedProbe);

/// <summary>
/// Deterministic test-only process runner. Fixtures are selected by the
/// executable, normalized argument vector, and classified probe. A missing
/// fixture is an explicit failure; it can never consume another probe's result
/// or silently turn an unmodeled operation into success.
/// </summary>
public sealed class ArgumentAwareProcessRunner : IProcessRunner
{
    private readonly Dictionary<FixtureKey, Queue<ProcessResult>> _fixtures = new();

    public List<RecordedProcessInvocation> Invocations { get; } = [];

    public void QueueResult(string fileName, IReadOnlyList<string> arguments, ProcessResult result, ProcessProbe? intendedProbe = null)
    {
        var probe = intendedProbe ?? Classify(fileName, arguments);
        var key = MakeKey(fileName, arguments, probe);
        if (!_fixtures.TryGetValue(key, out var queue))
        {
            queue = new Queue<ProcessResult>();
            _fixtures.Add(key, queue);
        }
        queue.Enqueue(result);
    }

    public ProcessResult Run(string fileName, IReadOnlyList<string> arguments, string? workingDirectory = null)
    {
        var probe = Classify(fileName, arguments);
        var key = MakeKey(fileName, arguments, probe);
        ProcessResult result;
        if (_fixtures.TryGetValue(key, out var queue) && queue.Count > 0)
        {
            result = queue.Dequeue();
        }
        else
        {
            result = new ProcessResult(127, "", $"No deterministic fixture for {probe}: {fileName} {string.Join(' ', arguments)}");
        }

        Invocations.Add(new RecordedProcessInvocation(fileName, arguments.ToArray(), workingDirectory, probe, result));
        return result;
    }

    public static ProcessProbe Classify(string fileName, IReadOnlyList<string> arguments)
    {
        var normalized = arguments.Select(argument => argument.Trim()).ToArray();
        var all = string.Join(" ", normalized);
        if (all.Contains("Get-AppxPackage", StringComparison.OrdinalIgnoreCase)) return ProcessProbe.AppxPackageTrust;
        if (all.Contains("Get-AuthenticodeSignature", StringComparison.OrdinalIgnoreCase)) return ProcessProbe.Authenticode;

        var executable = Path.GetFileName(fileName);
        if (executable.Equals("winget.exe", StringComparison.OrdinalIgnoreCase))
        {
            if (normalized.SequenceEqual(["--version"], StringComparer.OrdinalIgnoreCase)) return ProcessProbe.WingetVersion;
            if (normalized.Length >= 2 && normalized[0].Equals("source", StringComparison.OrdinalIgnoreCase) && normalized[1].Equals("list", StringComparison.OrdinalIgnoreCase)) return ProcessProbe.WingetSourceList;
            if (normalized.Length >= 1 && normalized[0].Equals("search", StringComparison.OrdinalIgnoreCase)) return ProcessProbe.WingetSearch;
            if (normalized.Length >= 1 && normalized[0].Equals("download", StringComparison.OrdinalIgnoreCase)) return ProcessProbe.WingetDownload;
        }
        if (normalized.SequenceEqual(["--version"], StringComparer.OrdinalIgnoreCase)) return ProcessProbe.Version;
        return ProcessProbe.Other;
    }

    private static FixtureKey MakeKey(string fileName, IReadOnlyList<string> arguments, ProcessProbe probe)
        => new(NormalizeExecutable(fileName), NormalizeArguments(arguments), probe);

    private static string NormalizeExecutable(string fileName)
    {
        try { return Path.GetFullPath(fileName).TrimEnd(Path.DirectorySeparatorChar).ToUpperInvariant(); }
        catch { return fileName.Trim().ToUpperInvariant(); }
    }

    private static string NormalizeArguments(IReadOnlyList<string> arguments)
        => string.Join("\u001f", arguments.Select(argument => argument.Trim()));
}
