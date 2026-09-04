# Recovery Model

Clean Reinstall, Uninstall, and Factory Reset create a metadata-only recovery ZIP before mutation. The package contains the ledger, payload hash, transaction ID, and instructions, never raw reusable private secrets. The operation log exposes failure and rollback limitations rather than claiming a hidden rollback succeeded.
