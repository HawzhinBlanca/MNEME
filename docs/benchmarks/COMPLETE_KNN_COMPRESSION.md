# Complete k-NN compression curve (CR-7)

Reproducible gate: `cargo test -p mneme-index --test complete_knn_compression -- --nocapture`

The test prints CSV rows (`COMPLETE_KNN_COMPRESSION_CSV`) with mean `|F|/n` over 12 random queries
on 48 synthetic points, comparing **exact** ball-tree pruning vs **JL conservative** pruning
(`ε = 0.2`, `m = recommended_target_dim(n, ε)`).

## Honest read (2026-06-11)

| Regime | What we observe | What we prove |
|---|---|---|
| Low `D` (≤16) | Exact pruning can achieve `|F|/n` well below 1 on separated synthetic data | Exact completeness (CR-1..CR-4) |
| High `D` (128) | Exact `|F|/n` → 1 (curse of dimensionality) | Pruning bound is correct but not succinct |
| JL conservative | May reduce `|F|/n` in moderate `D` on synthetic uniform cubes | **Never wrongly prunes** — matches brute-force k-NN |
| Raw embedding space (768–1536) | **Not benchmarked here** — expect little or no compression | JL sublinear + sound on real manifolds remains **open** |

**Dimension ceiling:** ship exact complete k-NN for low/moderate-dim or projected regimes where
tests show compression; do not claim succinct proofs in unconstrained high-dim embedding space
until the open problem in `docs/research/JL_DISTORTION_BOUND.md` closes.
