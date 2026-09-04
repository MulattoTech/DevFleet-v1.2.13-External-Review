# Installer Threat Model

- Corrupted embedded payload: rejected by SHA-256 before staging and again before extraction.
- Ambiguous ownership: destructive project-data scope is blocked unless a ledger resource has an explicit project ID and DevFleet ownership proof.
- Accidental cleanup: Factory Reset requires exact phrases; Clean Reinstall defaults to preservation.
- Interrupted mutation: transaction and log state are written before and after bounded operations; recovery packages are created before reinstall/removal.
- Secret leakage: recovery content is metadata-only and logs redact bearer tokens; private keys and reusable credentials are excluded.
- Supply chain: no third-party binaries are bundled; the build records the official SDK source and installer is explicitly unsigned.
