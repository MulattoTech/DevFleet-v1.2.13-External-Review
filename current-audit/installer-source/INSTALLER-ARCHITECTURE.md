# Installer Architecture

The wizard is a native WPF shell around bounded services: preflight, payload hash verification, staging, TAR extraction, recovery packaging, atomic ledger writes, ownership-aware plan generation, and selective cleanup. The embedded DevFleet TAR is verified before it is staged or extracted.

The application does not use a browser UI, winget, runtime network downloads, broad VM wildcards, or the user's entire SSH/VS Code configuration as cleanup targets.
