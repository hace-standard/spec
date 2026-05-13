# HACE Conformance Profiles

Profiles extend the baseline HACE requirements for specific regulatory and operational contexts. Every conforming HACE attestation declares exactly one profile via the `plug_conformance_profile` field. Verifiers enforce the additional requirements of the declared profile.

Profiles build on the baseline. An attestation that satisfies the requirements of a higher profile also satisfies BASELINE. An attestation may include fields beyond its declared profile's requirements; verifiers must not reject solely on the basis of extra fields.

---

## BASELINE

**URI:** `https://rankigi.com/hace/profiles/baseline-v1`

**Required fields:** all fields defined in SPEC.md Section 4.1.

**Additional requirements:** none beyond SPEC.md.

**Use case:** the default profile for any HACE attestation. Suitable for internal compliance, SOC 2 evidence collection, and general-purpose acknowledgment workflows.

---

## HIGH-ASSURANCE

**URI:** `https://rankigi.com/hace/profiles/high-assurance-v1`

**Status:** defined, not yet enforced by the reference implementation at the time of v1.0 publication.

**Additional required fields:**

| Field | Requirement |
|---|---|
| `transparency_log_receipt` | Must be present and non-null. Must include a valid inclusion proof in a recognized transparency log (Sigstore Rekor or equivalent). |

**Additional constraints:**

| Field | Constraint |
|---|---|
| `authentication_assurance_level` | NIST-AAL2 minimum. |

**Use case:** workflows where the signing event itself must be discoverable in a public log. Suitable for adversarial environments and for evidence packages intended to survive provider compromise.

---

## INSTITUTIONAL

**URI:** `https://rankigi.com/hace/profiles/institutional-v1`

**Status:** defined, not yet enforced by the reference implementation at the time of v1.0 publication.

**Additional required fields:**

| Field | Type | Definition |
|---|---|---|
| `acting_on_behalf_of` | object | The named authority under which the signer acts. Subfields: `name` (string), `role` (string), `authority_uri` (URI). |
| `delegation_chain` | array | Chain of authority from the named authority to the signer. Each element: `{ "from": URI, "to": URI, "authority_document": URI }`. |

**Use case:** workflows where the signer is not personally accountable but acts on behalf of an institution (audit committee, board, regulator, designated compliance officer). Suitable for SOX Section 302 / 906 certifications and equivalent institutional attestations.

---

## REGULATED

**URI:** `https://rankigi.com/hace/profiles/regulated-v1`

**Status:** defined, not yet enforced by the reference implementation at the time of v1.0 publication.

**Additional required fields:**

| Field | Type | Definition |
|---|---|---|
| `regulatory_regime` | string[] | One or more of: `SOX`, `HIPAA`, `EU-AI-ACT`, `PART-11`, `GDPR`, `PCI-DSS`. |

**Additional constraints:**

| Field | Constraint |
|---|---|
| `signature_meaning` | `APPROVAL` or `RESPONSIBILITY` only. |
| `identity_assurance_level` | NIST-IAL2 minimum. |
| `authentication_assurance_level` | NIST-AAL2 minimum. |

**Use case:** attestations bound to a specific regulatory regime. Verifiers can route REGULATED attestations through regime-specific retention and disclosure rules without parsing the underlying evidence.

---

## Combining profiles

Profiles compose by satisfying multiple sets of additional requirements in the same attestation. An attestation that includes a valid `transparency_log_receipt`, declares an `acting_on_behalf_of` block with a `delegation_chain`, and declares a `regulatory_regime` array satisfies HIGH-ASSURANCE, INSTITUTIONAL, and REGULATED simultaneously. The `plug_conformance_profile` field carries a single URI; in v1.0 a composed attestation declares the most specific profile it satisfies, and verifiers willing to enforce additional profile requirements may do so based on the presence of the required fields.

A future minor version of the standard may introduce a `plug_conformance_profiles` array field to declare multiple profiles formally.
