# Releasing

The canonical sequence is source tests, the current `VERSION` TAR, portable ZIP, unsigned build and
self-test, clean-room and maintenance E2E, Authenticode signing and timestamping,
signature verification, signed self-test, final hashes, installer-source ZIP, and audit
ZIP. A release stops on signing or required E2E failure. Fast rebuild is explicitly
unsigned developer output only.
