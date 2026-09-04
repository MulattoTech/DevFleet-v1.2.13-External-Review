# Building DevFleet Setup

Use a workspace-local .NET 8 SDK. The target PC does not need .NET because the published WPF installer is self-contained, single-file, and `win-x64`.

Full release:

```powershell
 .\Prepare-ReleaseInputs.ps1 -Mode Prepare -SourceRoot <source> -PreviousPortableZip <previous-portable.zip> -OutputDirectory <outputs> -SigningProfile PrivateSelfSigned -ProveIdempotent
 # Commit the prepared shipping inputs, then build only from the frozen commit.
 .\Build-Release.ps1 -SourceRoot <source> -PreviousPortableZip <previous-portable.zip> -OutputDirectory <outputs> -DotNet <dotnet.exe> -SigningProfile PrivateSelfSigned -VerifyFrozenInputs
```

Installer-only iteration after the embedded TAR is current:

```powershell
.\Fast-Rebuild-Installer.ps1 -OutputDirectory <outputs> -DotNet <dotnet.exe>
```
