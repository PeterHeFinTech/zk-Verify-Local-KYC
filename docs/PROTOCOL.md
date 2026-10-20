# Local source checking and issuer-authorized leaves

## Participants and trust

1. **Source authority:** maintains an independently approved source registry. It authenticates the applicant before binding a holder commitment in deployment. In this experiment the registry is imported from the user's two CSV files and approval/expiry are explicitly simulated. Only this authority has the Ed25519 source signing key.
2. **Holder:** owns raw U, random secret s and a source attestation. Runs normalization, local evidence checking, witness calculation and Groth16 proving.
3. **Issuer/tree operator:** pins the source public key. Receives only the signed attestation metadata, checks it, computes the leaf itself and authorizes insertion. Has a separate root-manifest signing key.
4. **Verifier:** pins the circuit verification-key hash, issuer and policy IDs; creates requests, accepts trusted roots, verifies proofs and atomically consumes requests.

All four roles are simulated on one computer here. Source keys are stored in `state/authority`, root signing key in `state/issuer`, wallets in `wallets`. Directory separation is not hardware/OS isolation against the account owner. No TEE or claim of tamper-proof user execution is made.

## Source protocol

* Holder generates a nonzero random field secret and C = Poseidon(holder-domain, s).
* Source authority resolves the approved record in its own registry. It computes U's digest from that record, not from a user-supplied digest. It signs the exact canonical JSON attestation: schema, simulation mode, handle, uDigest, C, issuedAt, expiry, verified, issuerId, policyId and revision.
* The attestation binds C to the approved U and timestamps. The source never needs s. The simulated importer orchestrates both roles but does not write holder secrets into the source registry.
* Holder checks the pinned source signature, canonicalizes its local U, recomputes uDigest and checks C against s. A changed client attribute or transaction fails this local check.
* Issuer independently verifies the signature, schema, IDs, timestamp ranges, approval and revision. It computes L itself. It never trusts a naked leaf or a client-side `verified=true` flag.

This meets **source-relative authenticity**: modifying U after source certification cannot preserve its authenticated digest under the hash assumptions. It does not establish real-world truth. If the source signs false data or an unauthorized holder commitment, the protocol cannot repair that failure. If the holder skips the local check, the issuer still verifies the source signature and independently constructs the leaf. A holder who learns the encoded credential attributes and secret can prove possession without retaining the original raw strings; the ZK claim is not possession of a passport image.

## Encoding and leaf

For each of the 12 source client fields, encode the exact decoded CSV string using SHA256 over canonical JSON `["client-field-v1", fieldName, value]`, reduced modulo the BN254 scalar field. Sort transaction records by transaction_id (consistent runtime collation), validate their schema and owner, and hash `["transactions-v1", transactions]` into a thirteenth field. Duplicate transaction IDs are rejected. No source flag is overwritten.

```
uDigest = Poseidon(u[0], ..., u[12])
C = Poseidon(202610201, s)
L = Poseidon(202610202, uDigest, C, issuedAt, expiry,
             verified, issuerId, policyId)
```

The local encoder, source encoder and issuer all use the same specified version. The 13 field encodings are private circuit inputs. SHA-256 and JSON parsing execute outside the circuit; the circuit binds their field values to the source-approved leaf. A fresh unpredictable secret hides leaves against simple enumeration of low-entropy personal attributes, subject to the construction's cryptographic assumptions; do not derive s from a phone number or client ID.

## Tree and root authorization

Depth 12, binary ordered Poseidon tree, zero empty leaf, recursively hashed empty subtrees. Initial import publishes one batch. SQLite stores `(level, index, version, value)`; retrieval uses the newest node at or before a requested version. A single replacement writes 13 nodes, not a full snapshot. Root manifests are signed by the issuer and include tree ID, issuer/policy IDs, version, time and update reason. The local verifier uses its trusted SQLite root registry; manifest signatures are supplied for external integrations, but external integrations must also obtain current acceptance/revocation policy. A signature on an old root alone is insufficient.

Only approved `verified=1` attestations enter the active tree. Expired credentials may appear for historical migration/testing, but cannot produce a proof for a current request. Revoked credentials have a zero leaf. Duplicate handles cannot create an additional independent credential; replacements require a strictly larger signed revision.

## Verification relation

Public signals, in exact order:

1. `response`: Poseidon(response-domain, s, context)
2. `issuerRoot`
3. `currentTime`: request creation time, seconds since Unix epoch
4. `validUntil`: request expiry, also a lower bound for credential expiry
5. `context`: hash of the server-created request, including random ID, audience, root version, root, times, pinned key hash and policy
6. `issuerId`
7. `policyId`

Private inputs: 13 encoded U fields, s, verified, issuedAt, expiry, 12 siblings and 12 direction bits.

Constraints: secret nonzero; verified = 1; all timestamps have 32-bit ranges; issuedAt <= currentTime <= validUntil <= expiry; recomputed leaf and path equal the public root; direction bits are Boolean; response is derived from secret and request context. Checking expiry against **validUntil**, not merely request creation time, prevents a credential expiring halfway through a still-valid request. Credentials with less than five minutes remaining may need to be renewed before this fixed-length request can be satisfied.

The verifier checks exact public-signal count and canonical field representation, approved root/version, issuer/policy IDs, request dates/context, pinned verification-key digest and the session-token hash. Groth16 is verified before an immediate SQLite transaction rechecks all mutable policy and marks the request accepted. This avoids two concurrent acceptances and revocation/expiry races during verification.

## Root lifecycle

Latest root: accepted until superseded or invalidated. Ordinary append: old root accepted for 600 seconds from supersession. Replacement/revocation: all preceding roots invalidated immediately. Requests live 300 seconds and cannot extend a retired root's acceptance window. Root history does not imply unlimited acceptance. Old nodes remain stored; production retention/compaction is out of scope.

## What is visible

* Source: approved U, holder commitment, attestation metadata, but not secret.
* Holder: own U, secret, attestation, own path, public root and request.
* Issuer: signed digest and metadata, holder commitment, leaves, nodes and handle association; no raw U or secret is required by issuer APIs.
* Verifier: proof, seven public signals, its own request state and bearer session token. It does not receive U, leaf, path, credential expiry, secret or witness.
* Local experiment operator: can read all local files. Role privacy is logical, not a claim against the local OS owner.

Public root hashing does not guarantee absolute anonymity. Issuer metadata, request timing, traffic, small populations and voluntary sharing remain relevant. Do not upload `wallets`, authority keys, witnesses or private submissions to GitHub.
