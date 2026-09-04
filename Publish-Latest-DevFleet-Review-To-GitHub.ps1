param(
    [string]$Repo = 'MulattoTech/DevFleet-v1.2.13-External-Review',
    [string]$PackageZip = '.\DevFleet-v1.2.13-External-GuestBootstrap-Review-20260904.zip'
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'GitHub CLI (gh) is required.' }
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'Git is required.' }
if (-not (Test-Path -LiteralPath $PackageZip -PathType Leaf)) { throw "Package not found: $PackageZip" }

gh auth status
if ($LASTEXITCODE -ne 0) { throw 'GitHub CLI authentication failed.' }

gh config set git_protocol https --host github.com
gh auth setup-git
if ($LASTEXITCODE -ne 0) { throw 'Unable to configure GitHub CLI as the HTTPS git credential helper.' }

$remote = "https://github.com/$Repo.git"
$root = Join-Path $env:TEMP ('DevFleet-Publish-' + [guid]::NewGuid().ToString('N'))
$extract = Join-Path $root 'extract'
$work = Join-Path $root 'repo'
New-Item -ItemType Directory -Path $extract,$work -Force | Out-Null

try {
    Expand-Archive -LiteralPath $PackageZip -DestinationPath $extract -Force

    $packageRoot = Get-ChildItem -LiteralPath $extract -Directory | Select-Object -First 1
    if (-not $packageRoot) { throw 'Package did not contain an expected top-level directory.' }

    # Publish the complete sanitized review package contents, not the local dev .git history.
    Copy-Item -Path (Join-Path $packageRoot.FullName '*') -Destination $work -Recurse -Force

    # Never carry nested git metadata.
    Get-ChildItem -LiteralPath $work -Directory -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object Name -eq '.git' |
        Remove-Item -Recurse -Force

    # Fail closed on obvious private-key / environment-secret material.
    $forbidden = Get-ChildItem -LiteralPath $work -File -Recurse -Force |
        Where-Object {
            $_.Extension -match '^(?i:\.pfx|\.p12|\.key|\.pem)$' -or
            $_.Name -eq '.env' -or
            $_.Name -match '^(?i:\.env\.(local|production|development|test|secret))$'
        }
    if ($forbidden) {
        throw "Potential secret material found; refusing upload:`n$($forbidden.FullName -join "`n")"
    }

    Push-Location $work
    try {
        git init -b main
        if (-not (git config user.name)) { git config user.name 'MulattoTech' }
        if (-not (git config user.email)) {
            $email = git config --global user.email
            if ($email) { git config user.email $email } else { git config user.email 'dylanmellor@gmail.com' }
        }

        git add --all
        git commit -m 'Replace external review with latest DevFleet v1.2.13 diagnostic snapshot'
        if ($LASTEXITCODE -ne 0) { throw 'Local snapshot commit failed.' }

        git remote add origin $remote

        # User explicitly authorized overwriting the existing external-review repo.
        git push --force --set-upstream origin main
        if ($LASTEXITCODE -ne 0) { throw 'Force push failed.' }

        gh repo view $Repo --json nameWithOwner,url,defaultBranchRef
        gh api "repos/$Repo/contents/01-AI-AGNOSTIC-TROUBLESHOOTING-PROMPT.md" --jq '{name:.name,path:.path,size:.size,sha:.sha}'
        if ($LASTEXITCODE -ne 0) { throw 'Remote verification failed.' }

        Write-Host ''
        Write-Host 'SUCCESS — latest sanitized DevFleet review snapshot replaced GitHub main.' -ForegroundColor Green
        Write-Host "https://github.com/$Repo"
        Write-Host 'External reviewers should begin with 01-AI-AGNOSTIC-TROUBLESHOOTING-PROMPT.md'
    }
    finally { Pop-Location }
}
finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
