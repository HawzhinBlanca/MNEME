# Complete k-NN compression curve (CR-7)

Reproducible gate: `cargo test -p mneme-index --test complete_knn_compression`.

Parameters: n=48, k=3, ε=0.2 (synthetic uniform [-1,1]^D).

| D | m | exact |F|/n | JL conservative |F|/n |
|---:|---:|---:|---:|
| 2 | 775 | 0.167 | 0.208 |
| 8 | 775 | 0.042 | 0.000 |
| 32 | 775 | 0.000 | 0.000 |
| 128 | 775 | 0.000 | 0.000 |

**Ceiling:** at D=128 exact |F|/n is high (curse of dimensionality); JL conservative may not beat exact in all regimes. Real 768–1536-d embeddings not measured here.
