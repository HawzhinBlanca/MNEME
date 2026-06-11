# The Verifiable Cognition Program

**Status:** research north-star. **Honesty boundary:** proves chain of custody — not semantic truth.

## 6. Integration track (software-feasible, not Trick 2–4 crypto)

Baseline: `master` @ `2d0fe1e5`. Wires cognition certs, complete retrieval, zkANN/beacon prototypes,
crossref vectors, CLI verify paths, and CI without frozen-seam roadmap rows.

| ID | Item | Status | Evidence |
|---|---|---|---|
| INT-1 | Cognition Certificate v1 offline verify | done | `cognition_cert.rs`, `mneme certify` / `verify-cert` |
| INT-2 | CompleteTopK cert + store certify | done | `cognition_cert_complete_topk.cbor` |
| INT-3 | zkANN + `complete_knn_tamper` (180 cases) | done | `validation-lane.sh tamper` |
| INT-4 | Beacon field-7 + `verify-cert --audit` | done | `beacon_spot_check.rs` |
| INT-5 | Pin `beacon_spot_check.cbor` + crossref stub | done | `wire_cert.rs`, `crossref_beacon_spot_check_fixture` |
| INT-6 | Crossref CompleteTopK verify | done | `wire_complete_knn.rs` |
| INT-7 | `cognition_cert_parse` fuzz | done | `fuzz/fuzz_targets/cognition_cert_parse.rs` |
| INT-8 | `vcp-integration-smoke.sh` in quick lane | done | `scripts/ci/vcp-integration-smoke.sh` |
| INT-9 | CLI verify-cert complete-topk + audit fixtures | done | `cli_e2e.rs` |
| INT-10 | Program doc + manifest evidence | done | this file; `manifest.yaml` |

### Parked

- §4 roadmap: D1, D2, B1, C1, A1, C2 — parallel agents
- Trick 2–4 crypto — parallel agents
- A2/Conn2–3 frozen seams — interface-change request
- drand BLS offline verify in crossref — deferred (zero new deps)
- Full exact-NN on lottery-selected audits in crossref — needs embedding sidecars

### Checkboxes

- [x] INT-1..INT-10 wired with tests and `validation-lane quick` smoke
- [x] `phase-program-gate.sh` runs `vcp-integration-smoke.sh`
- [x] `PHASE_IV_CROSSREF_NOTES.md` §6 beacon mirror landed
- [ ] PARK rows — deferred to named owners
