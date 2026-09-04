# Factory Reset

Control-plane removal requires `DELETE DEVFLEET`. Project data is off by default and additionally requires `DELETE DEVFLEET PROJECT DATA`, individual VERIFIED project selection, independently verified ownership, a restore-eligible exact backup whose archive hash and identities match, and submission of that exact backup ID/SHA to the Host Agent. Ambiguous or unrelated VMs cannot be selected.
