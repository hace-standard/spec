# HACE v1.0
## Human Acknowledgment of Chain Execution
### Wire Format Specification

---

## 1. Overview

HACE defines a wire format for a signed acknowledgment by a human compliance officer that they reviewed, and attest to, the sealed daily execution summary produced by a governance system. The standard specifies what the human signs, the structure of the signed payload, the rules for verifying the signature, and the rules for verifying the binding between the signature and the governance system's sealed summary. HACE is not a transport protocol, not an authentication protocol for the signer's session, and not a definition of what the governance system's sealed summary contains. HACE defines only the acknowledgment layer that sits between them.

---

## 2. Definitions

| Term | Definition |
|---|---|
| `governance_system` | The system producing the sealed execution summary. The system that mints `server_challenge` nonces and verifies inbound attestations. |
| `attestation_provider` | The compliance framework producing the human acknowledgment. The system holding the signing key. |
| `candidate` | The canonical JSON bytes the provider signs over. Delivered by the governance system in response to a candidate fetch. |
| `server_challenge` | A single-use nonce issued by the governance system inside each candidate response. |
| `attestation` | The signed acknowledgment payload submitted by the attestation provider to the governance system. |
| `verifier` | Any system validating a HACE attestation. Includes governance systems, auditors, regulators, and independent third parties. |
| `canonical JSON` | The deterministic JSON encoding used for hashing and signing. Keys sorted lexicographically by Unicode code point. No whitespace. UTF-8. Numbers in shortest round-trip form. |

---

## 3. Candidate Format

The governance system delivers a candidate response in canonical JSON. The byte sequence of this response is the payload the attestation provider signs over. Any modification, reordering, or whitespace change invalidates the resulting attestation.

### 3.1 Required fields

| Field | Type | Definition |
|---|---|---|
| `candidate_hash` | sha256hex | Hash of the sealed execution summary the governance system commits to. |
| `org_id` | uuid | Tenant identifier. |
| `plug_version` | string | HACE protocol version. `"1.0"` for this version. |
| `server_challenge` | base64url | Single-use nonce. 32 random bytes minimum. |
| `snapshot_id` | uuid | Governance period identifier. |
| `snapshot_date` | YYYY-MM-DD | The period date in ISO 8601 calendar form. |
| `ttl_expires_at` | RFC3339 | Wall-clock deadline after which the nonce expires. |

### 3.2 Optional fields

Governance systems may include additional fields in the candidate response. These fields become part of the signed bytes but are not required by HACE itself. RANKIGI's reference implementation includes:

| Field | Type | Definition |
|---|---|---|
| `exception_count` | integer | Count of non-verified closures in the period. |
| `exception_count_alerts` | integer | Count of critical alerts in the period. |
| `exception_manifest_hash` | sha256hex | Hash of the exception manifest sub-block. |
| `rankigi_schema` | string | RANKIGI-specific schema version. |
| `already_attested` | boolean | True if this snapshot has been attested previously. |
| `attestation_id` | uuid or null | Existing attestation id when `already_attested` is true. |

---

## 4. Attestation Format

The attestation provider POSTs a JSON object containing the following fields. All listed under "required" must be present. Verifiers reject attestations missing any required field.

### 4.1 Required fields

#### `plug_version` (string)
HACE protocol version. `"1.0"` for this version. Verifiers must reject attestations claiming a `plug_version` they do not support.

#### `plug_conformance_profile` (URI)
Profile URI declaring which conformance profile this attestation claims. Defaults to `https://rankigi.com/hace/profiles/baseline-v1` when omitted in the inbound payload. Profile-specific additional requirements apply per [PROFILES.md](PROFILES.md).

#### `snapshot_id` (uuid)
Must exactly match the `snapshot_id` value inside the signed `attestation_payload` and the value in the candidate response.

#### `org_id` (uuid)
Must exactly match the `org_id` value inside the signed `attestation_payload` and the value in the candidate response.

#### `candidate_hash` (sha256hex)
Must exactly match the governance system's snapshot hash for the declared period.

#### `attestation_payload` (base64)
The exact canonical bytes of the candidate response delivered by the governance system, base64-encoded. The signature is computed over the decoded bytes of this field. Providers must not re-canonicalize the payload before signing.

#### `attestation_signature` (base64)
Detached signature over the decoded `attestation_payload` bytes.

#### `attestation_signature_alg` (enum)
One of: `Ed25519`, `ML-DSA-65`, `RSASSA-PSS-SHA256`, `ECDSA-P256`, `ECDSA-P384`.

#### `signer_key_binding` (oneOf)
One of three shapes:

```json
{ "type": "x509", "certificate_chain": ["base64-DER", "base64-DER", ...] }
```
X.509 certificate chain. Leaf certificate at index 0. Intermediates at index 1 and beyond. Each entry is base64-encoded DER.

```json
{ "type": "jwk", "jwk": { ... } }
```
JSON Web Key per RFC 7517. Public key only.

```json
{ "type": "did_key", "did": "did:key:..." }
```
Decentralized Identifier. `did:key`, `did:web`, or another DID method whose public key the verifier can resolve.

#### `signer_identity` (object)
| Subfield | Type | Required |
|---|---|---|
| `display_name` | string | yes |
| `email` | string | yes |
| `identifier_uri` | string | no |
| `subject_dn` | string | no |
| `external_id` | string | no |

#### `signature_meaning` (enum)
One of: `APPROVAL`, `REVIEW`, `RESPONSIBILITY`, `AUTHORSHIP`. Per 21 CFR Part 11 §11.50(a). `APPROVAL` is the recommended value for period acknowledgment.

#### `identity_assurance_level` (enum)
One of: `NIST-IAL1`, `NIST-IAL2`, `NIST-IAL3`. Per NIST SP 800-63A.

#### `authentication_assurance_level` (enum)
One of: `NIST-AAL1`, `NIST-AAL2`, `NIST-AAL3`. Per NIST SP 800-63B.

#### `review_scope` (object)
A signed declaration of what the signer was shown.

| Subfield | Type | Required |
|---|---|---|
| `filters_applied` | string[] | yes |
| `total_chains_in_period` | number | yes |
| `exceptions_surfaced` | number | yes |
| `exceptions_bulk_attested` | number | yes |
| `exceptions_individually_reviewed` | number | yes |

#### `attestation_timestamp` (RFC3339, ms precision, UTC Z)
The moment the human applied their signature. Format: `YYYY-MM-DDTHH:MM:SS.mmmZ`. No offset notation.

#### `server_challenge` (base64url)
The nonce from the candidate response. Must also appear inside the decoded `attestation_payload` bytes. Verifiers compare the outer field to the inner field and reject any mismatch.

### 4.2 Optional fields

| Field | Type | Definition |
|---|---|---|
| `provider_id` | URI | Globally resolvable provider identity. `did:web:`, `https://.../.well-known/hace-provider`, or X.509 SubjectAltName URI. |
| `provider_attestation_id` | string | Provider internal reference. |
| `transparency_log_receipt` | object | Inclusion proof in an external transparency log such as Sigstore Rekor. Required by the HIGH-ASSURANCE profile. |
| `expires_at` | RFC3339 | When the attestation should be re-asserted. |

---

## 5. Signing Rules

1. Sign the raw bytes of `attestation_payload`. These are the base64-decoded canonical JSON bytes the governance system delivered. Do not re-canonicalize.
2. All timestamps must use `YYYY-MM-DDTHH:MM:SS.mmmZ` format. Millisecond precision. UTC Z suffix. No offset notation.
3. `server_challenge` must appear inside the signed `attestation_payload` bytes. Replay of any captured attestation fails nonce validation at the governance system.
4. When using x509 key binding: the leaf certificate is at index 0, intermediates at index 1 and beyond. All entries are base64-encoded DER format.
5. Step-up authentication at AAL2 minimum is recommended at the moment of signing for regulated use cases. The REGULATED profile requires it.
6. The `signature_meaning` value the signer applies must be consistent with the workflow they executed. APPROVAL is the recommended value for daily period acknowledgment.
7. Algorithm-specific rules:
   - Ed25519: RFC 8032 detached signature over the payload bytes.
   - ECDSA-P256 / ECDSA-P384: DER-encoded ECDSA signature over SHA-256 / SHA-384 of the payload.
   - RSASSA-PSS-SHA256: PSS padding, SHA-256 digest and MGF1.
   - ML-DSA-65: FIPS 204 detached signature. Since ML-DSA has no standardized X.509 binding at the time of this specification, the x509 `certificate_chain[0]` entry MAY carry the raw 1952-byte ML-DSA-65 public key for this version. This usage is provisional and subject to change once a standardized binding exists.

---

## 6. Verification Rules

A conforming verifier must perform all of the following checks before accepting an attestation as valid.

1. Parse `attestation_signature_alg` and route to the correct verification primitive.
2. Extract the public key from `signer_key_binding`. For `x509`, parse the leaf certificate and walk the chain validating each cert was issued by the next. For `jwk`, construct the key per RFC 7517. For `did_key`, resolve the DID using the appropriate method resolver.
3. Verify `attestation_signature` over the base64-decoded `attestation_payload` bytes using the extracted public key.
4. Parse the decoded `attestation_payload` as JSON. Verify the inner `server_challenge` field matches the outer `server_challenge` field of the attestation envelope.
5. Verify `candidate_hash` matches the governance system's sealed summary hash for the declared `snapshot_id` and `org_id`.
6. Verify `attestation_timestamp` is within the governance system's declared TTL for the snapshot (the candidate response's `ttl_expires_at`).
7. Verify `identity_assurance_level` and `authentication_assurance_level` meet any declared floor requirements. Floors are typically declared by the governance system per registered provider.
8. Verify `signature_meaning` is one of the four defined enum values.
9. Verify any additional profile-specific requirements declared in `plug_conformance_profile`.

A verifier failing any of these checks must reject the attestation.

---

## 7. Anti-Replay

The `server_challenge` nonce is issued by the governance system per candidate fetch. It is single-use. A verifier must confirm three things:

1. The nonce was issued by the governance system for this `(snapshot_id, org_id)` pair.
2. The nonce has not been previously redeemed.
3. The nonce appears inside the signed `attestation_payload` bytes.

The governance system marks the nonce as redeemed atomically during attestation ingest. A nonce that fails any of the three checks results in a 401 response and the attestation is not persisted.

These three checks together prevent replay of any captured attestation. Even if a provider's signing key is compromised, an attacker cannot replay a captured attestation against a different snapshot, against the same snapshot at a later time, or against a snapshot the provider never legitimately attested. The replay surface is limited to the single-use window between nonce issuance and the governance system's TTL expiry.

---

## 8. Schema Version Evolution

`plug_version` identifies the HACE protocol version. The value is a string of the form `MAJOR.MINOR`. Verifiers must reject attestations claiming a `plug_version` they do not support.

- Future MAJOR versions may add required fields, change field semantics, or remove fields.
- Future MINOR versions may add optional fields within a major line without a version bump becoming mandatory.
- Verifiers must accept attestations with optional fields they do not recognize. They must not reject solely because of unrecognized optional fields.
- Verifiers must reject attestations missing any field required by the declared `plug_version`.

The `plug_conformance_profile` field is a URI. Profile URIs are versioned independently of `plug_version`. A v1.0 attestation may declare any registered v1.x profile.

---

## 9. Errors

A governance system acting as a verifier returns the following HTTP statuses:

| Status | Meaning |
|---|---|
| 401 | Provider not registered, signature verification failed, or `server_challenge` invalid or already redeemed. |
| 409 | Snapshot already attested. Response includes existing `attestation_id` and `attested_at`. |
| 422 | `candidate_hash` mismatch, assurance level below declared floor, TTL window expired, `signature_meaning` invalid, or `plug_version` unsupported. |

---

## 10. References

- 21 CFR Part 11 §11.50 (electronic signature semantics)
- NIST SP 800-63A (identity assurance levels)
- NIST SP 800-63B (authentication assurance levels)
- RFC 7517 (JSON Web Key)
- RFC 8032 (Ed25519)
- RFC 8259 (JSON)
- RFC 3339 (timestamp format)
- FIPS 204 (ML-DSA)
- W3C DID Core 1.0
- Sigstore Rekor (transparency log inclusion proofs)
