using System.IO;
using System.Diagnostics;
using System.Text;
using System.Windows;
using System.Windows.Controls;

namespace DevFleet.Setup;

public partial class MainWindow : Window
{
    private readonly string[] _pages = ["Welcome", "Action", "Preflight", "Tailscale", "Scope", "Review", "Execute", "Finish"];
    private int _page;
    private PreflightReport _preflight = new();
    private InstallerPlan? _plan;
    private IReadOnlyList<DiscoveredProject> _projects = [];
    private bool _executing;
    private bool _tailscaleBusy;
    private CancellationTokenSource? _tailscaleCancellation;
    private int _progress;
    private bool _deferNetworkPairing;
    private Uri? _tailscaleAuthenticationUri;

    public MainWindow()
    {
        InitializeComponent();
        VersionText.Text = $"DevFleet {PayloadManifest.DevFleetVersion}  ·  Installer {PayloadManifest.InstallerVersion}  ·  Official-source connected setup";
        ModeCombo.ItemsSource = Enum.GetValues<InstallerMode>();
        ModeCombo.SelectedItem = InstallerMode.Diagnostics;
        RoleCombo.ItemsSource = new[] { "Primary / Desktop", "Laptop / Surrogate" };
        RoleCombo.SelectedIndex = 0;
    }

    private InstallerMode CurrentMode => ModeCombo.SelectedItem is InstallerMode mode ? mode : InstallerMode.Diagnostics;

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        NextButton.IsEnabled = false;
        DetectedSummary.Text = "Running read-only preflight off the UI thread…";
        try
        {
            var result = await Task.Run(() => (Report: PreflightService.Run(), Projects: (IReadOnlyList<DiscoveredProject>)new ProjectDiscoveryService().Discover()));
            _preflight = result.Report;
            _projects = result.Projects;
            ProjectList.ItemsSource = _projects;
            DetectedSummary.Text = $"Existing DevFleet: {_preflight.ExistingDevFleetVersion} · Role: {_preflight.DetectedRole} · Admin: {_preflight.Administrator}";
            PreflightText.Text = PreflightService.ToText(_preflight);
        }
        catch (Exception ex)
        {
            DetectedSummary.Text = "Preflight failed safely; no mutation was attempted.";
            PreflightText.Text = $"Read-only preflight failed: {ex.Message}";
        }
        var args = Environment.GetCommandLineArgs();
        _deferNetworkPairing = args.Any(a => a.Equals("--defer-network-pairing", StringComparison.OrdinalIgnoreCase));
        DeferNetworkPairingCheck.IsChecked = _deferNetworkPairing;
        var requested = Array.FindIndex(args, a => a.Equals("--action", StringComparison.OrdinalIgnoreCase));
        if (requested >= 0 && requested + 1 < args.Length && Enum.TryParse<InstallerMode>(args[requested + 1], true, out var action)) ModeCombo.SelectedItem = action;
        var requestedRole = Array.FindIndex(args, a => a.Equals("--role", StringComparison.OrdinalIgnoreCase));
        if (requestedRole >= 0 && requestedRole + 1 < args.Length)
        {
            var role = args[requestedRole + 1];
            var index = Array.IndexOf((string[])RoleCombo.ItemsSource, role);
            if (index >= 0) RoleCombo.SelectedIndex = index;
        }
        if (args.Any(a => a.Equals("--elevated-resume", StringComparison.OrdinalIgnoreCase)))
            DetectedSummary.Text += " · UAC elevation resumed with the reviewed action and role";
        NextButton.IsEnabled = true;
        RefreshPage();
    }

    private void RefreshPage()
    {
        PageKicker.Text = $"STEP {_page + 1} OF {_pages.Length} · {_pages[_page].ToUpperInvariant()}";
        WelcomePanel.Visibility = _page == 0 ? Visibility.Visible : Visibility.Collapsed;
        ActionPanel.Visibility = _page == 1 ? Visibility.Visible : Visibility.Collapsed;
        PreflightPanel.Visibility = _page == 2 ? Visibility.Visible : Visibility.Collapsed;
        TailscalePanel.Visibility = _page == 3 ? Visibility.Visible : Visibility.Collapsed;
        ScopePanel.Visibility = _page == 4 ? Visibility.Visible : Visibility.Collapsed;
        ReviewPanel.Visibility = _page == 5 ? Visibility.Visible : Visibility.Collapsed;
        ExecutePanel.Visibility = _page >= 6 ? Visibility.Visible : Visibility.Collapsed;
        DangerPanel.Visibility = _page == 4 && CurrentMode == InstallerMode.FactoryReset ? Visibility.Visible : Visibility.Collapsed;
        BackButton.IsEnabled = _page > 0 && !_executing;
        NextButton.Visibility = _page < 6 ? Visibility.Visible : Visibility.Collapsed;
        ExecuteButton.Visibility = _page == 6 && CurrentMode != InstallerMode.Diagnostics ? Visibility.Visible : Visibility.Collapsed;
        ExportButton.Visibility = _page == 2 ? Visibility.Visible : Visibility.Collapsed;
        CopyButton.Visibility = _page is 2 or 5 or 6 ? Visibility.Visible : Visibility.Collapsed;
        PageTitle.Text = _page switch
        {
            0 => "Prepare a safe DevFleet operation",
            1 => "Choose the exact action and role",
            2 => "Review non-mutating preflight",
            3 => "Authenticate or deliberately defer Tailscale pairing",
            4 => CurrentMode == InstallerMode.FactoryReset ? "Select preservation and destructive scope" : "Confirm preservation and recovery",
            5 => "Review the exact transaction plan",
            6 => "Execute and verify",
            _ => "Operation complete"
        };
        PageDescription.Text = _page == 4 && CurrentMode == InstallerMode.FactoryReset ? "Factory Reset is visually distinct and requires exact typed confirmations. Ambiguous resources remain untouched." : "Every mutation is hash-verified, ownership-aware, logged, and recoverable where applicable.";
        foreach (var item in new[] { StepWelcome, StepAction, StepPreflight, StepScope, StepReview, StepExecute }) item.Foreground = (System.Windows.Media.Brush)FindResource("MutedBrush");
        var active = _page switch { 0 => StepWelcome, 1 => StepAction, 2 => StepPreflight, 3 or 4 => StepScope, 5 => StepReview, _ => StepExecute };
        active.Foreground = (System.Windows.Media.Brush)FindResource("AccentBrush"); active.FontWeight = FontWeights.Bold;
        if (_page == 5) BuildPlanAndShow();
    }

    private void ModeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (IsLoaded) RefreshPage();
    }

    private void NextButton_Click(object sender, RoutedEventArgs e)
    {
        if (_page == 5 && (_plan is null || !_plan.IsAllowed)) { BuildPlanAndShow(); return; }
        if (_page < 7) { _page++; RefreshPage(); }
    }

    private void BackButton_Click(object sender, RoutedEventArgs e)
    {
        if (_page > 0) { _page--; RefreshPage(); }
    }

    private void BuildPlanAndShow()
    {
        var selected = ProjectList.SelectedItems.Cast<DiscoveredProject>().Select(p => p.ProjectId).ToArray();
        _deferNetworkPairing = DeferNetworkPairingCheck.IsChecked == true;
        _plan = PlanService.Build(CurrentMode, PreserveProjectsCheck.IsChecked == true, PreserveBackupsCheck.IsChecked == true, RemovePrerequisitesCheck.IsChecked == true, ProjectDataCheck.IsChecked == true, VerifiedBackupCheck.IsChecked == true, ControlPhraseBox.Text, ProjectPhraseBox.Text, selected, _deferNetworkPairing, RootfulDockerAcknowledgeCheck.IsChecked == true);
        RebootCheckpointService.BindPlanIfPresent(_plan, RoleCombo.SelectedItem?.ToString() ?? "Primary / Desktop");
        PlanText.Text = PlanService.ToText(_plan);
        PlanStatus.Text = _plan.IsAllowed ? "PASS — plan is eligible for execution after final review." : "BLOCKED — resolve every blocker before execution.";
        PlanStatus.Foreground = (System.Windows.Media.Brush)FindResource(_plan.IsAllowed ? "AccentBrush" : "DangerBrush");
    }

    private async void ExecuteButton_Click(object sender, RoutedEventArgs e)
    {
        if (_executing) return;
        BuildPlanAndShow();
        if (_plan is null || !_plan.IsAllowed) { MessageBox.Show(this, PlanService.ToText(_plan ?? new InstallerPlan()), "Execution blocked", MessageBoxButton.OK, MessageBoxImage.Warning); return; }
        if (MessageBox.Show(this, "Execute the reviewed plan now? Diagnostics remains read-only; cleanup actions use only the displayed ownership scope.", "Confirm exact plan", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        if (!ElevationService.IsAdministrator && !TestEnvironment.IsTestProcess)
        {
            // The unelevated UI may validate the plan, but it must not create
            // protected staging. The elevated continuation reopens and
            // independently verifies the embedded payload.
            ElevationService.RelaunchVerified(RoleCombo.SelectedItem?.ToString() ?? "Primary / Desktop", CurrentMode, _deferNetworkPairing);
            Close();
            return;
        }
            _executing = true; _progress = 0; _page = 6; RefreshPage(); ExecuteButton.IsEnabled = false; OperationLog.Clear();
            try
            {
                var plan = _plan;
                var role = RoleCombo.SelectedItem?.ToString() ?? "Standalone / unknown";
                var result = await Task.Run(() => InstallerEngine.Execute(plan!, role, ReportProgress));
            var rebootRequired = LifecycleEngine.LastExecution?.ExitCode == 3010 || File.Exists(RebootCheckpointService.Path);
            if (rebootRequired)
            {
                ReportProgress("REBOOT REQUIRED: the verified checkpoint is preserved; restart this same candidate after Windows reboots.");
                OperationStatus.Text = "Reboot required; checkpoint preserved";
                OperationProgress.Value = 95;
                _page = 6;
                RefreshPage();
                return;
            }
            ReportProgress($"VERIFIED COMPLETE: {result}"); OperationProgress.Value = 100; OperationStatus.Text = "Completed and verified"; _page = 7; RefreshPage();
        }
        catch (Exception ex)
        {
            ReportProgress($"FAILED — no unplanned continuation: {ex}"); OperationStatus.Text = "Failed; evidence preserved in the log"; OperationProgress.Value = 0;
        }
        finally { _executing = false; ExecuteButton.IsEnabled = true; BackButton.IsEnabled = true; }
    }

    private void ReportProgress(string message)
    {
        Dispatcher.Invoke(() => { _progress = Math.Min(95, _progress + 13); OperationProgress.Value = _progress; OperationStatus.Text = message; OperationLog.AppendText(message + Environment.NewLine); OperationLog.ScrollToEnd(); });
    }

    private void ExportButton_Click(object sender, RoutedEventArgs e)
    {
        var directory = Path.Combine(AppPaths.StateRoot, "Diagnostics"); Directory.CreateDirectory(directory); var stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
        var json = Path.Combine(directory, $"preflight-{stamp}.json"); var text = Path.Combine(directory, $"preflight-{stamp}.txt"); StateStore.WriteJsonAtomically(json, _preflight); File.WriteAllText(text, PreflightService.ToText(_preflight));
        MessageBox.Show(this, $"Preflight exported to:\n{text}\n{json}", "Read-only report exported", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void CopyButton_Click(object sender, RoutedEventArgs e)
    {
        var content = _page == 2 ? PreflightText.Text : _page == 5 ? PlanText.Text : OperationLog.Text; Clipboard.SetText(content); OperationStatus.Text = "Diagnostics copied to clipboard";
    }

    private async void TailscaleSignIn_Click(object sender, RoutedEventArgs e)
    {
        if (_tailscaleBusy) return;
        _tailscaleBusy = true; _tailscaleCancellation = new CancellationTokenSource(); var sourceButton = sender as Button; if (sourceButton is not null) sourceButton.IsEnabled = false;
        try
        {
        var dependency = DependencyService.Catalog.Single(x => x.Name == "Tailscale"); var detected = new DependencyService().Detect(dependency);
        if (!detected.Compatible) { TailscaleStatusText.Text = "Tailscale is missing or outdated. The Dependencies stage will install/update it from the official source before pairing."; return; }
        TailscaleStatusText.Text = "Starting bounded Tailscale authentication…";
        var auth = await TailscaleAuthenticationService.BeginAsync(new ProcessRunner(), detected.ExecutablePath, _tailscaleCancellation.Token); _tailscaleAuthenticationUri = auth.AuthenticationUri; OpenTailscaleAuthButton.IsEnabled = _tailscaleAuthenticationUri is not null; TailscaleStatusText.Text = $"{auth.State}: {auth.Detail}";
        }
        catch (OperationCanceledException) { TailscaleStatusText.Text = "Tailscale authentication cancelled."; }
        catch (Exception ex) { TailscaleStatusText.Text = $"Tailscale authentication failed: {ex.Message}"; }
        finally { _tailscaleBusy = false; _tailscaleCancellation?.Dispose(); _tailscaleCancellation = null; if (sourceButton is not null) sourceButton.IsEnabled = true; }
    }

    private void OpenTailscaleAuth_Click(object sender, RoutedEventArgs e)
    {
        if (_tailscaleAuthenticationUri is null || !_tailscaleAuthenticationUri.Host.Equals("login.tailscale.com", StringComparison.OrdinalIgnoreCase)) return;
        Process.Start(new ProcessStartInfo { FileName = _tailscaleAuthenticationUri.AbsoluteUri, UseShellExecute = true });
    }

    private async void CheckTailscale_Click(object sender, RoutedEventArgs e)
    {
        if (_tailscaleBusy) return;
        _tailscaleBusy = true; _tailscaleCancellation = new CancellationTokenSource(); var sourceButton = sender as Button; if (sourceButton is not null) sourceButton.IsEnabled = false;
        try
        {
        var dependency = DependencyService.Catalog.Single(x => x.Name == "Tailscale"); var detected = new DependencyService().Detect(dependency);
        if (!detected.Found) { TailscaleStatusText.Text = "Not installed yet."; return; }
        var result = await new ProcessRunner().RunAsync(detected.ExecutablePath, ["status", "--json"], cancellationToken: _tailscaleCancellation.Token); TailscaleStatusText.Text = result.ExitCode == 0 ? "Authenticated — Tailscale status returned successfully." : "Authentication required or Tailscale service unavailable.";
        }
        catch (OperationCanceledException) { TailscaleStatusText.Text = "Tailscale status check cancelled."; }
        catch (Exception ex) { TailscaleStatusText.Text = $"Tailscale status failed: {ex.Message}"; }
        finally { _tailscaleBusy = false; _tailscaleCancellation?.Dispose(); _tailscaleCancellation = null; if (sourceButton is not null) sourceButton.IsEnabled = true; }
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        if (_tailscaleBusy) { _tailscaleCancellation?.Cancel(); return; }
        if (_executing) { MessageBox.Show(this, "The current transaction is active. Wait for its bounded operation to finish; no forced reboot or blind cancellation is issued.", "Transaction in progress", MessageBoxButton.OK, MessageBoxImage.Information); return; }
        Close();
    }
}
