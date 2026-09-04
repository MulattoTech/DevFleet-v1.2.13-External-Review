# WinGet recovery

WinGet is healthy only when version, `source list`, and an exact package search succeed.
Missing, Broken, SourceBroken, or incompatible WinGet is not silently treated as healthy.
The supported Microsoft repair path uses Microsoft.WinGet.Client and
`Repair-WinGetPackageManager -Force -Latest`; source reset is conservative and requires
administrator authority. If repair remains unavailable, mandatory dependencies use
their allowlisted official-vendor resolver.
