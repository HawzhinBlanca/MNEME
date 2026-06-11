# Trick #4 — Byzantine Inference Consistency (Research Prototype)

**Status:** Prototype in `mneme-index` (`byzantine_inference`, cognition cert field 8).  
**Date:** 2026-06-11.

## Idea

Run the same certified context through **M ≥ 2** independent model endpoints at **temperature 0**,
bind each replica's `output_digest = BLAKE3(model_output)` into cognition certificate field 8,
and require **unanimous** output agreement at offline verification.

**Honesty:** consistency evidence only — not correctness, not semantic truth. Full M-way collusion breaks the guarantee.

## Wire (field 8)

Binding domain: `MNEME-BYZANTINE-INF-BIND-v1`. See `byzantine_inference.rs` for map layout.

## CLI

`mneme verify-cert --byzantine CERT`

## Done vs parked

| Done | Parked |
|------|--------|
| Field 8 wire + binding + unanimous verify | Live multi-operator orchestration |
| `verify-cert --byzantine` | Normative logit-commitment crypto |
| Research doc + manifest pin | Frozen Root `context_digest` binding |
| Crossref decode stub | TCB integration |
| Integration tests | VCP D1 MuHash convergence |
