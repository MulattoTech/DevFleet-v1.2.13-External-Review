[CmdletBinding()]
param(
    [string]$VmName = 'devfleet-primary',
    [string]$HostAddress = 'mulattotechbox',
    [int]$Port = 8790,
    [switch]$PreviewOnly,
    [switch]$AllowPermanentDelete
)

$ErrorActionPreference = 'Stop'
if ($VmName -notmatch '^devfleet-primary$') { throw 'Only the existing primary dashboard VM may be configured by this utility.' }
$multipass = Get-MultipassExe
$installRoot = 'C:\ProgramData\DevFleetHostAgent'
$tokenPath = Join-Path $installRoot 'token.txt'
$url = "http://${HostAddress}:$Port"

if (-not (Test-Path -LiteralPath $tokenPath)) { throw 'Host-agent token is missing; install the host agent first.' }
$token = (Get-Content -LiteralPath $tokenPath -Raw).Trim()
if ($token.Length -lt 40) { throw 'Host-agent token is unexpectedly short.' }
$overlay = [ordered]@{
    host_control_enabled = $true
    host_control_url = $url
    host_control_token = $token
    expected_host_name = $env:COMPUTERNAME
    host_agent_timeout_seconds = 30
    host_resource_policy = [ordered]@{
        policy_version = '1.0.0'
        physical_floor_min_gb = 8
        physical_floor_percent = 0.10
        commit_headroom_floor_min_gb = 16
        commit_headroom_percent = 0.20
        commit_usage_limit_percent = 80
        reserved_logical_processors = 2
        minimum_free_disk_gb = 50
        maximum_vm_count = 4
        maximum_parallel_provisioning = 1
        max_project_cpus = 6
        max_project_memory_gb = 12
        max_project_disk_gb = 120
    }
}
if ($AllowPermanentDelete) { $overlay.allow_permanent_delete = $true }
if ($PreviewOnly) {
    [ordered]@{ok=$true;preview_only=$true;vm_name=$VmName;host_control_url=$url;expected_host_name=$env:COMPUTERNAME;gpu_passthrough=$false;allow_permanent_delete=[bool]$AllowPermanentDelete} | ConvertTo-Json -Compress
    exit 0
}

$payloadPath = Join-Path $env:TEMP "devfleet-host-control-$([guid]::NewGuid().ToString('N')).json"
try {
    [IO.File]::WriteAllText($payloadPath,($overlay | ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding($false)))
    & $multipass transfer $payloadPath "${VmName}:/tmp/devfleet-host-control.json" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to transfer the host-control overlay to the primary VM.' }
    $remote = @'
set -Eeuo pipefail
sudo -n python3 - /tmp/devfleet-host-control.json <<'PY'
import grp, json, os, tempfile
config_path = '/etc/devfleet/config.json'
overlay_path = '/tmp/devfleet-host-control.json'
with open(config_path, encoding='utf-8') as fh:
    config = json.load(fh)
with open(overlay_path, encoding='utf-8') as fh:
    config.update(json.load(fh))
fd, temp_path = tempfile.mkstemp(prefix='.config-', dir='/etc/devfleet')
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        json.dump(config, fh, separators=(',', ':'))
        fh.flush()
        os.fsync(fh.fileno())
    os.chown(temp_path, 0, grp.getgrnam('devrunner').gr_gid)
    os.chmod(temp_path, 0o640)
    os.replace(temp_path, config_path)
except Exception:
    try: os.unlink(temp_path)
    except FileNotFoundError: pass
    raise
PY
sudo -n rm -f /tmp/devfleet-host-control.json
'@
    & $multipass exec $VmName -- bash -lc $remote | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'The primary VM rejected the atomic host-control configuration update.' }
    & $multipass exec $VmName -- sudo -n systemctl restart devfleet.service | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'The primary DevFleet service did not restart after host-control configuration.' }
    $health = (& $multipass exec $VmName -- curl -fsS --connect-timeout 5 http://127.0.0.1:8787/healthz | Out-String).Trim()
    [ordered]@{ok=$true;configured_vm=$VmName;host_control_url=$url;dashboard_health=$health;gpu_passthrough=$false} | ConvertTo-Json -Compress
} finally {
    if (Test-Path -LiteralPath $payloadPath) { [IO.File]::Delete($payloadPath) }
}
