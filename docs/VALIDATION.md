# Delivery validation — 2026-10-20

## Executed successfully

* `npm test`: 13 reported unit/protocol tests passed, zero failures.
* `npm run test:e2e`: 18 checks passed, including real Groth16 proof generation/verification and invalid witness rejection. See `reports/latest-e2e.json` for the successful run and its directory.
* `npm run test:integration`: 8 workflow/API checks passed. A temporary loopback server accepted exactly one of two concurrent submissions of the same actual proof. The test shut the server down. See `reports/latest-integration.json`.
* `node scripts/cli.mjs demo`: successfully generated and accepted an actual proof for an imported, unexpired credential.
* `node scripts/cli.mjs demo 20`: exited nonzero at the expiry constraint, as expected.
* Groth16 zkey consistency check reported `ZKey Ok` against the compiled R1CS and local Powers of Tau file.

Main source import: 2,000 clients and 50,000 transactions; 2,000 simulated approved credentials, 1,900 unexpired and 100 expired at import. Main tree is depth 12 (capacity 4,096). Integration tests use separate state and do not modify the main credential tree.

## Observed single-run timing (not a benchmark)

One successful local demonstration recorded approximately 192 ms witness calculation, 897 ms proving, 27 ms policy/cryptographic verification, and 724 bytes for compact proof JSON. These were measured during development, with no repetitions or hardware normalization. Do not use them as production throughput claims. Later runs and the revised in-memory witness path can differ. Metrics are saved per proof directory.

## Failures encountered and resolved

* A naive initial inspection of client CSV columns was unsuitable because names can contain quoted commas. Actual ingestion uses a tested quoted-CSV parser; final source counts come from that parser.
* snarkjs file-based witness calculation on an invalid input triggered a Node 25 unclosed-file-handle error. Witness calculation now completes in memory before any witness file is written. Negative circuit tests pass without that failure.
* The generated witness calculator uses CommonJS. The setup writes a local CommonJS package declaration in the generated directory.
* The sandbox initially prohibited opening a loopback port. The authorized local integration run was subsequently executed successfully; no data was uploaded to external services.

Earlier failed-run reports are retained for diagnosis. Use `latest-e2e.json` and `latest-integration.json` to identify the final successful runs.

## Explicitly not established

No real person was identity-verified; no official sanctions database was queried. The CSV source authority, credential approval and validity dates are simulations. The code binds approved source claims to leaves and proves secret possession/membership; it cannot establish objective truth of a dishonest source's assertions. No hardware enclave, remote attestation or operating-system isolation among the co-located roles was tested. No independent cryptographic audit or production multi-party setup was performed. No billion-user scaling claim is made.

The development scripts and documentation are delivered, not a public deployment or browser UI. The verifier API is loopback-only and optional; the full workflow is available through the CLI.
