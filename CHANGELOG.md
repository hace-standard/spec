# Changelog

## v1.0, May 2026

Initial publication.

### Required fields

`plug_version`, `plug_conformance_profile`, `snapshot_id`, `org_id`, `candidate_hash`, `attestation_payload`, `attestation_signature`, `attestation_signature_alg`, `signer_key_binding`, `signer_identity`, `signature_meaning`, `identity_assurance_level`, `authentication_assurance_level`, `review_scope`, `attestation_timestamp`, `server_challenge`.

### Supported signing algorithms

`Ed25519`, `ML-DSA-65`, `RSASSA-PSS-SHA256`, `ECDSA-P256`, `ECDSA-P384`.

### Defined profiles

`baseline-v1`, `high-assurance-v1`, `institutional-v1`, `regulated-v1`.

Enforced at launch: `baseline-v1` only. The other three profile URIs are defined and reserved; reference-implementation enforcement follows in subsequent minor releases as the first provider requesting each profile lands.

### Reference implementations

- RANKIGI governance layer at rankigi.com (governance system + verifier).
- Reference verifier scripts at `verify/verify.py` and `verify/verify.ts`.
