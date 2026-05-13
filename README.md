# HACE
## Human Acknowledgment of Chain Execution

HACE is an open standard for human acknowledgment of governed AI execution.

A governance system computes a sealed daily summary of everything it observed. A compliance framework has a human review that summary, sign over the exact bytes they were shown, and declare what they were shown, on whose authority they signed, and what their signature means.

Any compliance framework can connect to any governance system without bespoke integration. The governance system does not own the signature. The compliance framework does not own the evidence. Each is independently verifiable.

### Why HACE exists

AI agents are executing real actions in production. Hashing and chaining those actions proves what happened. But proof of execution is not the same as human accountability. HACE closes that gap.

HACE is the human-side complement to cryptographic proof. It defines the wire format for a signed acknowledgment that any conforming verifier can check.

### Relationship to KYA

HACE and KYA (Know Your Agent, github.com/kya-standard/spec) are companion standards.

KYA answers: what is this agent and what is it allowed to do?

HACE answers: did a named human, at a declared assurance level, acknowledge what this agent did?

### Conformance

A conforming HACE attestation must:
- Include all required fields defined in [SPEC.md](SPEC.md)
- Sign over the canonical bytes of the governance system's candidate response
- Echo the `server_challenge` nonce inside the signed bytes
- Declare a `signature_meaning` from the defined enum
- Declare identity and authentication assurance levels

A conforming HACE verifier must:
- Validate the signature against the signer's certificate chain
- Validate the `server_challenge` was issued by the governance system and has not been redeemed
- Validate the `candidate_hash` matches the governance system's snapshot
- Validate `signature_meaning` is a defined value
- Enforce declared assurance floor requirements

### Repository layout

```
SPEC.md            full wire format specification
PROFILES.md        conformance profiles
schema/            JSON Schema definitions
  hace-v1.0.json
  candidate-v1.0.json
verify/            reference verifier implementations
  verify.py
  verify.ts
CHANGELOG.md       version history
LICENSE            MIT
```

### First implementation

The first production implementation of HACE is the RANKIGI governance layer at rankigi.com. The RANKIGI ingest route at `/api/v1/attestations` accepts any conforming HACE v1.0 attestation. The reference candidate-delivery endpoint is at `/api/v1/snapshots/{snapshot_id}/candidate`.

### Status

Version: 1.0
Status: Published
Date: May 2026

### License

MIT. See [LICENSE](LICENSE).
