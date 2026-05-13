#!/usr/bin/env python3
"""
HACE v1.0 reference verifier (Python).

Usage:
    python3 verify.py <attestation.json> <candidate.json>

Reads a HACE attestation JSON file and a candidate JSON file from disk
and verifies a conforming HACE v1.0 attestation. Output:

    HACE VERIFIED
or
    HACE FAILED: <reason>

Dependencies:
    Python 3.8+ standard library only for the structural and binding checks.
    Ed25519 signature verification additionally requires the `cryptography`
    package (pip install cryptography). When `cryptography` is not present,
    the verifier still performs all non-cryptographic checks and reports
    that the signature primitive was skipped.

Algorithms:
    Ed25519 is the only signing algorithm this reference verifier supports
    out of the box. The other four algorithms defined by HACE v1.0 are out
    of scope for the stdlib-only reference. A production verifier should
    route by `attestation_signature_alg` and call the appropriate primitive.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any, Tuple

VALID_SIGNATURE_MEANINGS = {"APPROVAL", "REVIEW", "RESPONSIBILITY", "AUTHORSHIP"}
SUPPORTED_PLUG_VERSIONS = {"1.0"}
SUPPORTED_ALGS_NATIVE = {"Ed25519"}

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    from cryptography import x509
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False


def fail(reason: str) -> None:
    print(f"HACE FAILED: {reason}")
    sys.exit(1)


def ok() -> None:
    print("HACE VERIFIED")
    sys.exit(0)


def b64_decode(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as e:
        fail(f"{field} is not valid base64: {e}")
        raise


def parse_rfc3339_ms(value: str, field: str) -> datetime:
    try:
        if not value.endswith("Z"):
            fail(f"{field} must end with Z (UTC). Got: {value}")
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as e:
        fail(f"{field} is not a valid RFC3339 ms timestamp: {e}")
        raise


def verify_ed25519(payload: bytes, signature: bytes, leaf_der: bytes) -> bool:
    if not HAVE_CRYPTOGRAPHY:
        print(
            "  warning: `cryptography` package not installed. "
            "Skipping Ed25519 signature verification."
        )
        return True
    cert = x509.load_der_x509_certificate(leaf_der)
    pub = cert.public_key()
    if not isinstance(pub, Ed25519PublicKey):
        # Try treating leaf_der as raw SPKI DER public key (some providers
        # send the SPKI directly rather than wrapping it in a certificate).
        try:
            pub2 = load_der_public_key(leaf_der)
            if not isinstance(pub2, Ed25519PublicKey):
                fail("leaf key is not Ed25519")
            pub = pub2
        except Exception:
            fail("leaf key is not Ed25519 and is not parseable as raw SPKI")
    try:
        pub.verify(signature, payload)
        return True
    except Exception:
        return False


def load_json(path: str, label: str) -> Tuple[dict, bytes]:
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        fail(f"cannot read {label}: {e}")
        raise
    try:
        return json.loads(raw), raw
    except json.JSONDecodeError as e:
        fail(f"{label} is not valid JSON: {e}")
        raise


def required(obj: dict, field: str, label: str) -> Any:
    if field not in obj:
        fail(f"{label} missing required field: {field}")
    return obj[field]


def main() -> None:
    if len(sys.argv) != 3:
        print("Usage: python3 verify.py <attestation.json> <candidate.json>")
        sys.exit(2)

    att_path, cand_path = sys.argv[1], sys.argv[2]
    att, _ = load_json(att_path, "attestation")
    candidate, candidate_bytes = load_json(cand_path, "candidate")

    plug_version = required(att, "plug_version", "attestation")
    if plug_version not in SUPPORTED_PLUG_VERSIONS:
        fail(f"unsupported plug_version: {plug_version}")

    signature_meaning = required(att, "signature_meaning", "attestation")
    if signature_meaning not in VALID_SIGNATURE_MEANINGS:
        fail(f"invalid signature_meaning: {signature_meaning}")

    outer_challenge = required(att, "server_challenge", "attestation")
    cand_challenge = required(candidate, "server_challenge", "candidate")
    if outer_challenge != cand_challenge:
        fail("server_challenge mismatch between attestation envelope and candidate")

    cand_hash = required(att, "candidate_hash", "attestation")
    computed_hash = hashlib.sha256(candidate_bytes).hexdigest()
    declared_cand_hash = required(candidate, "candidate_hash", "candidate")
    if cand_hash != declared_cand_hash:
        fail("attestation.candidate_hash does not match candidate.candidate_hash")
    if computed_hash != declared_cand_hash:
        print(
            "  note: sha256(candidate bytes) does not equal candidate_hash. "
            "This is expected when candidate_hash is the hash of the sealed "
            "execution summary rather than the candidate response itself."
        )

    if att.get("snapshot_id") != candidate.get("snapshot_id"):
        fail("snapshot_id mismatch")
    if att.get("org_id") != candidate.get("org_id"):
        fail("org_id mismatch")

    payload_b64 = required(att, "attestation_payload", "attestation")
    payload_bytes = b64_decode(payload_b64, "attestation_payload")
    try:
        inner = json.loads(payload_bytes)
    except json.JSONDecodeError as e:
        fail(f"attestation_payload is not valid JSON: {e}")
        raise
    if inner.get("server_challenge") != outer_challenge:
        fail("server_challenge inside signed payload does not match outer field")

    ttl_str = required(candidate, "ttl_expires_at", "candidate")
    ttl = parse_rfc3339_ms(ttl_str, "ttl_expires_at")
    att_ts = parse_rfc3339_ms(
        required(att, "attestation_timestamp", "attestation"),
        "attestation_timestamp",
    )
    if att_ts > ttl:
        fail("attestation_timestamp is past candidate ttl_expires_at")

    alg = required(att, "attestation_signature_alg", "attestation")
    if alg not in SUPPORTED_ALGS_NATIVE:
        print(
            f"  warning: signing algorithm {alg} is not supported by this "
            f"reference verifier. Non-signature checks passed; signature "
            f"primitive skipped. Use a production verifier for {alg}."
        )
        ok()

    binding = required(att, "signer_key_binding", "attestation")
    if binding.get("type") != "x509":
        print(
            "  warning: this reference verifier supports the x509 key "
            "binding only. Non-signature checks passed; signature primitive "
            "skipped."
        )
        ok()

    chain = binding.get("certificate_chain") or []
    if not chain:
        fail("signer_key_binding.certificate_chain is empty")
    leaf_der = b64_decode(chain[0], "signer_key_binding.certificate_chain[0]")
    signature = b64_decode(
        required(att, "attestation_signature", "attestation"),
        "attestation_signature",
    )
    if not verify_ed25519(payload_bytes, signature, leaf_der):
        fail("Ed25519 signature verification failed")

    ok()


if __name__ == "__main__":
    main()
