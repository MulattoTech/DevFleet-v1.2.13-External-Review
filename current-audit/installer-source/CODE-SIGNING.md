# Authenticode signing

Release signing uses Microsoft Azure Artifact Signing with SignTool, SHA-256, and the
RFC 3161-compatible `http://timestamp.acs.microsoft.com` timestamp service, or a
legitimate certificate-store identity with protected private key. The normal
`Build-Release.ps1` fails closed when no identity is configured. Only
`-UnsignedDeveloperBuild` permits an unsigned inner-loop build; it is not release
eligible. Verify with `signtool verify /pa /v` and `Get-AuthenticodeSignature` and run
the signed self-test before calculating the distributed hash.

Private/personal releases may explicitly use `-SigningProfile PrivateSelfSigned`.
That profile creates or reuses one exact-subject, RSA-3072, SHA-256 Code Signing
certificate in `CurrentUser/My`, requires a non-exportable private key, persists only
public metadata under `%LOCALAPPDATA%\DevFleet\Signing\PrivateSelfSigned`, and trusts
only the exported public certificate in the signing user's Root and Trusted Publishers
stores. Windows may require the interactive owner-consent prompt for the Root import;
the release gate blocks until that exact thumbprint is present. It never creates a PFX
and never enables public promotion. This profile means
cryptographically signed and valid only on explicitly trusted personal/test systems;
it does not mean publicly trusted publisher identity.
