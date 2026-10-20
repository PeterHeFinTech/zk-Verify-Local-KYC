# zk-Verify Local KYC

A local, executable KYC credential workflow with authenticated source records, private holder secrets, Poseidon Merkle trees, Circom constraints and Groth16 proofs. This is an independent project; the original `zk-Verify` directory is not modified.

**Trust boundary:** this delivery uses a **simulated source authority** over the supplied CSV files. It demonstrates authenticating an approved dataset and rejecting subsequent tampering. It does not establish that the dataset describes real people, that a client owns an identity, or that the source sanctions labels are correct. A CSV is not an identity document. The authority's private key must not reside on a user's machine in a real deployment. All roles are co-located here for controlled evaluation, not isolated from a malicious local administrator.

## Start with the already prepared project

```bash
cd zk-Verify-Local-KYC
npm run demo
```

This selects the valid example in `data/manifest.json`, retrieves a version-consistent path, creates a five-minute request, generates a real Groth16 proof locally and verifies it once. Each run writes a new directory under `proofs/`. No original records are uploaded. `proof.json` and `public.json` are the cryptographic submission; files marked `private`, `witness.wtns`, and session tokens must remain private.

Run an expired credential (expected failure):

```bash
node scripts/cli.mjs demo 20
```

Generated expiry is relative to the import date. Credentials eventually expire; do not fake the verifier clock to make expired credentials pass. Create a new isolated experiment or use the approved update workflow.

## Dependencies and fresh installation

The GitHub repository contains source code, circuits, tests and documentation. Input CSVs, local identities/keys, wallets, witnesses, proofs, reports, generated proving artifacts and installed dependencies are excluded. A fresh clone must install dependencies, run setup and import its own authorized input files before running the demonstration. To specify an input directory, run `node scripts/cli.mjs import /absolute/path/to/archive` after setup.

Required: Node.js >=22.13 (this run uses 25.6.0), Circom 2.2.3 on PATH, and the exact npm packages in `package.json`. Node's SQLite API may print an experimental-feature warning on some releases.

The delivered directory reuses the existing installed packages through a `node_modules` symlink. No new packages were installed. **Do not run npm install through that symlink**, because it could modify the original dependency directory. On a fresh standalone copy without the symlink:

```bash
npm install
circom --version
npm run setup
npm run import
npm run demo
```

`scripts/link-existing-dependencies.mjs [existing-node_modules]` is an alternative for this machine. It checks exact top-level versions and refuses to replace an existing `node_modules` entry. A portable reproducible dependency installation should generate and retain its own lockfile with `npm install` in a standalone copy.

`npm run setup` compiles the circuit, generates a **local single-operator development ceremony**, performs phase-2 contribution and verifies the resulting zkey. It never prompts for entropy: cryptographic randomness is supplied internally. These keys are NOT suitable for production assurance. The setup script refuses to overwrite a completed setup. Updating a circuit requires a new versioned setup and verifier profile.

## Source data and simulation

Default input directory: `~/Downloads/archive`. You can pass another directory to the import command.

* `clients_with_fatf_ofac.csv`: 2,000 original client rows.
* `transactions_with_fatf_ofac.csv`: 50,000 original transaction rows, joined by `client_id`.

The importer uses a quoted-CSV parser, not `split(',')`. It rejects duplicate identifiers, malformed rows, nonbinary flags and orphan transactions. It preserves string values, including names containing commas. Original files are copied byte-for-byte to `data/raw/`; SHA-256 checksums and counts are in `data/manifest.json`.

Each holder's U contains one complete original client record and all supplied transactions associated with that client. This demonstrates binding both inputs, not transaction-based identity verification. Twelve client fields are individually domain-separated SHA-256-to-field encodings. The sorted transaction array is encoded as a thirteenth field. Poseidon over the 13 fields produces `uDigest`. The circuit checks the encoded fields, not a raw JSON parser or SHA-256 preimage computation. Its substantive holder-security property is possession of the secret tied to an issuer-approved digest.

Simulated fields are **separate from U**:

* `issuedAt`: import time minus 365 days (a simulated historical issuance date).
* `expiry`: every twentieth client expired one day before import; others expire 90 days after import.
* `verified`: 1 for every client under default `simulate-clear`, as requested. This is a simulated approval scenario, **not a claim that the source flags are all clear**.
* Secret: a cryptographically random private value, not deterministically derived from public client IDs.
* Source and root signatures: generated by local simulation keys.

The original client table includes 55 `sanctions_flag=1` rows; the original transaction table includes 1,790 `ofac_match_flag=1` rows. Those values are NOT erased. Optional `source-flags` simulation approves only clients with `sanctions_flag=0` and no supplied transaction carrying `ofac_match_flag=1`. Neither policy constitutes real KYC or complete AML.

To run an independent import with another policy, use a **new** directory:

```bash
ZK_STATE_DIR=/absolute/path/to/new-experiment node scripts/cli.mjs import "$HOME/Downloads/archive" source-flags
```

Use the same `ZK_STATE_DIR` for all subsequent commands for that experiment. Existing state is never overwritten by import.

## Step-by-step CLI

```bash
node scripts/cli.mjs status
node scripts/cli.mjs local-check 1
node scripts/cli.mjs path 1
node scripts/cli.mjs request
```

The last command prints an absolute request-file path. Use that actual path:

```bash
node scripts/cli.mjs prove 1 /absolute/path/to/request.private.json
node scripts/cli.mjs verify /absolute/path/to/submission.private.json
```

Verification is single-use. Verifying the same accepted submission again should fail. Request IDs and roots alone do not authenticate ownership: the request has a separate 256-bit session token. In deployment this token belongs to the verifier's authenticated session; anyone who steals it and the proof can act as its bearer.

## Updates and revocation

`update` is an **authority/operator command**, not a user self-approval endpoint. Prepare a JSON source record with the same `handle`, complete updated `U`, `issuedAt`, `expiry`, `verified: 1`, and a `revision` exactly one larger than the current registry revision. Have the authority approve it, then:

```bash
node scripts/cli.mjs update 1 /absolute/path/to/approved-source-record.json
node scripts/cli.mjs revoke 20
```

Updates reauthenticate source data, regenerate the authorized leaf, change only the 13 nodes along a depth-12 path and publish a new signed root. Revocation replaces the leaf with zero. Both operations conservatively invalidate **all earlier roots in this tree**, affecting other pending users too. They must fetch new paths and requests. This is an explicit security/availability tradeoff, not anonymous per-user revocation.

If a crash interrupted wallet/source file distribution after the database committed a replacement, run `node scripts/cli.mjs recover 1 /absolute/path/to/approved-source-record.json`. Recovery checks the record against the already committed signed envelope and retained secret; it does not issue a new approval.

To add an operator-approved new source record with a new handle and revision 1, use `node scripts/cli.mjs enroll-source /absolute/path/to/approved-source-record.json`. This is another authority-only simulation operation; it is not a public self-registration API.

For future onboarding, `Store.change(authenticatedEnvelope)` accepts a new, source-authenticated handle and appends its leaf. Normal append preserves earlier roots for ten minutes after they are superseded. Historical nodes are retained for snapshot retrieval; the acceptance window is not the same as a deletion/retention policy.

The latest root remains acceptable until replaced or invalidated; it does not expire ten minutes after creation. Retired roots expire exactly 600 seconds after retirement. Multiple root versions can have the same root value; policy binds the **version and request**, not just the hash.

## Loopback verifier API

```bash
npm start
```

Binds only `127.0.0.1:8788`. The access token is generated at `state/verifier-access.private.json`; it is not printed. Send it in `Authorization: Bearer ...`.

* `GET /status`: current public root and aggregate workflow counts.
* `POST /requests`: create a request and return its session token to the authenticated caller.
* `POST /verify`: submit the contents of `submission.private.json`.

No route serves source records, private keys, wallets or witnesses. Browser-origin requests are rejected and body size is capped at 64 KiB. This is a local development adapter, not an institutional authentication gateway. Do not expose it publicly. Production needs TLS, managed identities, session binding, quotas, separate role processes, secret management, backup and monitoring.

## Tests

```bash
npm test
npm run test:e2e
npm run test:integration
```

Unit/protocol tests cover CSV parsing, source/holder tampering, paths, persistent updates, root TTL, policy pinning, request ownership, expiry, replay races, immediate revocation and restart. They inject a mock cryptographic verifier to isolate state-machine behavior; they are not evidence of Groth16 correctness by themselves.

End-to-end tests use the compiled circuit and actual proving key, generate and independently verify a Groth16 proof, alter public signals, and reject invalid witnesses. They use the imported valid/expired example wallets. Reports, successful proof files and failing private inputs are written to `reports/`; failures are not replaced with fake proofs.

Integration tests create a separate state directory under `reports/`, import both source files under the flag-derived simulation policy, exercise authority-approved updates/recovery/new issuance, and start a temporary authenticated loopback server. They submit a real proof concurrently and require exactly one acceptance, then shut the server down. They do not revoke or modify the main demonstration wallets.

## File map

| File | Responsibility |
| --- | --- |
| `lib/data.mjs` | CSV parsing, canonical U encoding, input manifests |
| `lib/crypto.mjs` | Poseidon, domain separation, Ed25519 signatures, random secrets |
| `lib/protocol.mjs` | Source attestation, local U check, witness-input preparation |
| `lib/store.mjs` | Versioned SQLite Merkle nodes, roots, credential updates, atomic request acceptance |
| `lib/runtime.mjs` | Artifact integrity checks, actual witness/proof generation and verification |
| `circuits/kyc.circom` | Private membership, approval, expiry, secret and request-binding constraints |
| `scripts/cli.mjs` | Import, local check, request, prove, verify, update, revoke and demo |
| `scripts/setup.mjs` | Circuit compilation and development-only setup |
| `server/main.mjs` | Authenticated loopback verifier API |
| `docs/PROTOCOL.md` | Trust model, data visibility, signatures and precise statements |
| `docs/WORKFLOW.md` | Revised end-to-end workflow and version management |

The tree has capacity 4,096, depth 12. This accommodates the supplied 2,000 clients; it is not a claim of testing hundreds of millions of users. Larger depth changes the circuit and requires new keys. A path and node update are O(log N); source ingestion and initial tree construction are O(N) plus transaction processing. Persistent storage and audit retention also grow with updates.

## Security limits

* No real identity provider, government registry, live sanctions feed, TEE, biometric verification or remote attestation is integrated.
* A locally executed checker is not trusted merely because it runs on the holder's machine. Authenticity comes from the **pinned source signature and issuer validation**, not the checker UI.
* Source signatures authenticate the source's assertion, not objective reality or completeness outside the imported dataset.
* Files use restrictive local permissions but are not encrypted at rest; all roles run as the same OS user in this demonstration.
* The authority and issuer can link handles to issued leaves. ZK does not erase issuer knowledge. Path retrieval and network metadata can leak activity in a future remote service.
* Secrets may be shared voluntarily; this is credential possession, not a non-transferability proof.
* An authenticated source binding to the real applicant is assumed in deployment. Selecting a demo client ID does not implement that ownership verification.
* Local single-operator setup and custom circuits have not received independent cryptographic review.

References: [Circom public/private signals](https://docs.circom.io/circom-language/signals/), [snarkjs Groth16 usage](https://github.com/iden3/snarkjs).
