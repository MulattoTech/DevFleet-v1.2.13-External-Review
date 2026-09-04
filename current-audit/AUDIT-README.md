# DevFleet v1.2.13 — Universal AI Audit Bundle

This is the one canonical source, tooling, compact-evidence, and audit bundle for independent review by ChatGPT, Gemini, Grok, Claude, or another reviewer.

Status: BLOCKED
DevFleet: 1.2.13 / installer: 1.4.1
Git: v1.2.13-audit-remediation / d65560c1ec7bf97f4002a9e9a438fbc1b25f22bd
Current candidate: True; source changed: False; rebuild required: False

The bundle intentionally excludes compiled release binaries, nested archives, VM images, caches, credentials, tokens, and raw giant transcripts. The exact binary names, sizes, hashes, PE/AuthentiCode result, embedded TAR identity, and release/tooling fingerprints are in CURRENT-CANDIDATE.json.

The complete release-E2E automation source is under automation/release-e2e/. Historical evidence is explicitly marked and is not promoted to current-candidate PASS.

Clean-extraction entrypoint: python release-tooling/run_portable_audit_tests.py --root . --output portable-audit-test-result.json
Bundle validator: python source/tools/validate_ai_audit_bundle.py --archive DevFleet-v1.2.13-AI-Audit-LATEST.zip --mode diagnostic
