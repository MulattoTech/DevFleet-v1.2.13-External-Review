# Troubleshooting

Use read-only preflight first. For dependency failures record detected path/version,
WinGet health, official source, download hash/signer, installer exit code, rediscovered
path/version, and reboot state. Network failures use bounded retries and preserve the
resumable transaction. Do not delete arbitrary AppX/WinGet state or use production as a
destructive test environment.
