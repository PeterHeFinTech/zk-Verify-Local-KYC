# Implemented zk-Verify workflow

## 1. Input and source attestation

Import both CSV files without changing their original fields. Each U consists of a client row and its associated transaction rows. Generate separately labeled demonstration approval and expiry fields. The source authority certifies U's digest, holder commitment and metadata with an Ed25519 signature. This is a simulated source certification, not proof of real-world identity.

## 2. Local inspection and leaf generation

The holder checks the signed source evidence against local U and its secret. The issuer repeats signature and policy checks without needing the secret or raw U, independently computes the leaf and authorizes it. Placing a checker in the user's environment is not itself a trust mechanism. The signed evidence is the trust anchor.

## 3. Tree construction

The issuer builds a depth-12 tree for the initial batch and publishes a signed root manifest. Leaf values are at the bottom level; internal nodes are hashes of ordered child nodes. The root commits to the approved set under this issuer/policy, not universally true identities.

## 4. Request and snapshot

Verifier creates a random single-use request binding a root version, audience, current time, expiry and verification-key hash. Holder obtains a path for **that exact version**, not an independently fetched latest root. The request contains a private session token.

## 5. Local proof generation

Developers compile Circom once and prepare matching Groth16 keys; ordinary users do not redefine their own verification circuit. WASM calculates the witness locally. snarkjs uses Groth16 and the proving key to generate proof and public signals. Private input and witness files remain local.

## 6. Verification

Verifier checks root policy and request ownership, verifies Groth16, rechecks mutable policy atomically, and consumes the request. It learns that the request holder knows a secret for an approved, sufficiently long-lived credential in the selected tree. It does not independently learn that a physical person is present, that a credential cannot be transferred, or that the source never made a mistake.

## 7. Updates

Authority approves revised source data and issues a higher revision. The issuer replaces the corresponding leaf, updates its ancestor path in O(log N) node writes, invalidates earlier roots and publishes a new root. Existing requests using those roots fail safely. Wallet and source registry updates are written atomically per file but not transactionally with the SQLite database; a crash between those operations requires replaying the approved credential distribution from issuer state. See the recovery command below.

## 8. Revocation and ordinary additions

An ordinary new leaf does not invalidate existing credentials, so recently retired roots can remain acceptable for ten minutes. Revocation and replacement have a stricter policy: old roots are immediately invalidated, sacrificing in-flight request availability. An independent privacy-preserving revocation tree is a possible future extension, not implemented here.

## Recovery and deployment boundary

Keep source registry, issuer database, holder wallets and artifact profile backed up consistently. SQLite protects its own state transitions; it does not create a distributed transaction across independently administered roles. The supplied recovery CLI validates an operator-provided approved record against the already committed issuer attestation before updating local distribution files. Never fabricate a secret during recovery; losing the secret requires a newly authorized credential.

Institutional deployment additionally needs an actual trusted source with applicant authentication, separate OS/service identities, authenticated transports, protected keys, explicit data retention, monitored queues, rate limiting and a reviewed setup ceremony. This project deliberately provides a locally executable trust model rather than claiming those integrations exist.
