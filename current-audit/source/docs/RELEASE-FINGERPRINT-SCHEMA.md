# Release fingerprint schema

Schema 2 is the current DevFleet release identity format. It removes checkout-local
absolute artifact paths and host filesystem permission bits from the hashed identity.
Artifacts are identified by logical name, byte length, and SHA-256. Source file modes
come from the same hook-mode contract used to write the canonical TAR and portable
archive: contracted template hooks are `0755`, and every other shipping file is
`0644`.

Schema 1 records remain valid only as explicitly historical evidence. They must not
be promoted as the identity of a current candidate because their IDs can vary by
checkout location and host permission representation.
