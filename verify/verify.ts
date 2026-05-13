#!/usr/bin/env -S node --experimental-strip-types
/**
 * HACE v1.0 reference verifier (TypeScript / Node).
 *
 * Usage:
 *   node verify.ts <attestation.json> <candidate.json>
 *
 * Reads a HACE attestation JSON file and a candidate JSON file from disk
 * and verifies a conforming HACE v1.0 attestation. Output:
 *
 *   HACE VERIFIED
 * or
 *   HACE FAILED: <reason>
 *
 * Dependencies: Node 18+ built-ins only (crypto, fs). No external packages.
 *
 * Algorithms: Ed25519 via Node's crypto.X509Certificate / crypto.verify.
 * The other four HACE v1.0 algorithms (ML-DSA-65, RSASSA-PSS-SHA256,
 * ECDSA-P256, ECDSA-P384) are out of scope for this reference; a production
 * verifier should route by attestation_signature_alg and call the
 * appropriate primitive.
 */

import * as crypto from "node:crypto";
import { readFileSync } from "node:fs";

const VALID_SIGNATURE_MEANINGS = new Set([
  "APPROVAL",
  "REVIEW",
  "RESPONSIBILITY",
  "AUTHORSHIP",
]);
const SUPPORTED_PLUG_VERSIONS = new Set(["1.0"]);
const SUPPORTED_ALGS_NATIVE = new Set(["Ed25519"]);

interface JsonObject {
  [key: string]: unknown;
}

function fail(reason: string): never {
  console.log(`HACE FAILED: ${reason}`);
  process.exit(1);
}

function ok(): never {
  console.log("HACE VERIFIED");
  process.exit(0);
}

function required<T = unknown>(obj: JsonObject, field: string, label: string): T {
  if (!(field in obj)) {
    fail(`${label} missing required field: ${field}`);
  }
  return obj[field] as T;
}

function loadJson(path: string, label: string): { obj: JsonObject; bytes: Buffer } {
  let bytes: Buffer;
  try {
    bytes = readFileSync(path);
  } catch (e) {
    fail(`cannot read ${label}: ${(e as Error).message}`);
  }
  try {
    const obj = JSON.parse(bytes.toString("utf-8")) as JsonObject;
    return { obj, bytes };
  } catch (e) {
    fail(`${label} is not valid JSON: ${(e as Error).message}`);
  }
}

function parseRfc3339Ms(value: string, field: string): Date {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    fail(`${field} is not a valid RFC3339 ms timestamp: ${value}`);
  }
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) {
    fail(`${field} is not a valid date: ${value}`);
  }
  return d;
}

function b64Decode(value: string, field: string): Buffer {
  try {
    return Buffer.from(value, "base64");
  } catch (e) {
    fail(`${field} is not valid base64: ${(e as Error).message}`);
  }
}

function verifyEd25519(
  payload: Buffer,
  signature: Buffer,
  leafDer: Buffer,
): boolean {
  let publicKey: crypto.KeyObject;
  try {
    const cert = new crypto.X509Certificate(leafDer);
    publicKey = cert.publicKey;
  } catch {
    // Fall back: treat leafDer as raw SPKI DER public key.
    try {
      publicKey = crypto.createPublicKey({ key: leafDer, format: "der", type: "spki" });
    } catch (e) {
      fail(`cannot parse leaf as X.509 cert or SPKI: ${(e as Error).message}`);
    }
  }
  if (publicKey.asymmetricKeyType !== "ed25519") {
    fail(`leaf key is not Ed25519 (got ${publicKey.asymmetricKeyType})`);
  }
  return crypto.verify(null, payload, publicKey, signature);
}

function main(): void {
  const [, , attPath, candPath] = process.argv;
  if (!attPath || !candPath) {
    console.log("Usage: node verify.ts <attestation.json> <candidate.json>");
    process.exit(2);
  }

  const { obj: att } = loadJson(attPath, "attestation");
  const { obj: candidate, bytes: candidateBytes } = loadJson(candPath, "candidate");

  const plugVersion = required<string>(att, "plug_version", "attestation");
  if (!SUPPORTED_PLUG_VERSIONS.has(plugVersion)) {
    fail(`unsupported plug_version: ${plugVersion}`);
  }

  const signatureMeaning = required<string>(att, "signature_meaning", "attestation");
  if (!VALID_SIGNATURE_MEANINGS.has(signatureMeaning)) {
    fail(`invalid signature_meaning: ${signatureMeaning}`);
  }

  const outerChallenge = required<string>(att, "server_challenge", "attestation");
  const candChallenge = required<string>(candidate, "server_challenge", "candidate");
  if (outerChallenge !== candChallenge) {
    fail("server_challenge mismatch between attestation envelope and candidate");
  }

  const candHash = required<string>(att, "candidate_hash", "attestation");
  const declaredCandHash = required<string>(candidate, "candidate_hash", "candidate");
  if (candHash !== declaredCandHash) {
    fail("attestation.candidate_hash does not match candidate.candidate_hash");
  }
  const computedHash = crypto.createHash("sha256").update(candidateBytes).digest("hex");
  if (computedHash !== declaredCandHash) {
    console.log(
      "  note: sha256(candidate bytes) does not equal candidate_hash. " +
        "This is expected when candidate_hash is the hash of the sealed " +
        "execution summary rather than the candidate response itself.",
    );
  }

  if (att.snapshot_id !== candidate.snapshot_id) {
    fail("snapshot_id mismatch");
  }
  if (att.org_id !== candidate.org_id) {
    fail("org_id mismatch");
  }

  const payloadB64 = required<string>(att, "attestation_payload", "attestation");
  const payloadBytes = b64Decode(payloadB64, "attestation_payload");
  let inner: JsonObject;
  try {
    inner = JSON.parse(payloadBytes.toString("utf-8")) as JsonObject;
  } catch (e) {
    fail(`attestation_payload is not valid JSON: ${(e as Error).message}`);
  }
  if (inner.server_challenge !== outerChallenge) {
    fail("server_challenge inside signed payload does not match outer field");
  }

  const ttl = parseRfc3339Ms(
    required<string>(candidate, "ttl_expires_at", "candidate"),
    "ttl_expires_at",
  );
  const attTs = parseRfc3339Ms(
    required<string>(att, "attestation_timestamp", "attestation"),
    "attestation_timestamp",
  );
  if (attTs.getTime() > ttl.getTime()) {
    fail("attestation_timestamp is past candidate ttl_expires_at");
  }

  const alg = required<string>(att, "attestation_signature_alg", "attestation");
  if (!SUPPORTED_ALGS_NATIVE.has(alg)) {
    console.log(
      `  warning: signing algorithm ${alg} is not supported by this ` +
        "reference verifier. Non-signature checks passed; signature " +
        "primitive skipped. Use a production verifier for " + alg + ".",
    );
    ok();
  }

  const binding = required<JsonObject>(att, "signer_key_binding", "attestation");
  if (binding.type !== "x509") {
    console.log(
      "  warning: this reference verifier supports the x509 key binding " +
        "only. Non-signature checks passed; signature primitive skipped.",
    );
    ok();
  }
  const chain = (binding.certificate_chain as string[]) ?? [];
  if (chain.length === 0) {
    fail("signer_key_binding.certificate_chain is empty");
  }
  const leafDer = b64Decode(chain[0], "signer_key_binding.certificate_chain[0]");
  const signature = b64Decode(
    required<string>(att, "attestation_signature", "attestation"),
    "attestation_signature",
  );
  if (!verifyEd25519(payloadBytes, signature, leafDer)) {
    fail("Ed25519 signature verification failed");
  }

  ok();
}

main();
