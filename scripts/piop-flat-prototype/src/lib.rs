use blake3::Hasher;
use std::time::Instant;
pub const PIOP_FLAT_HONESTY: &str =
    "Flat-index sidecar lab only — NOT PIOP/SNARK; not on recall path; proves nothing.";
const SIDECAR_DOMAIN: &[u8] = b"MNEME-PIOP-FLAT-SIDECAR-v1";
pub fn run_microbench(cardinality: usize, dim: u32) -> (f64, f64) {
    let mut entries: Vec<([u8; 32], Vec<u8>)> = (0..cardinality)
        .map(|i| {
            (
                hash_tag(b"OBJ", &(i as u64).to_le_bytes()),
                bench_embedding(i, dim),
            )
        })
        .collect();
    entries.sort_by_key(|(id, _)| *id);
    let query = bench_embedding(cardinality / 2, dim);
    let t0 = Instant::now();
    let mut h = Hasher::new();
    h.update(SIDECAR_DOMAIN);
    for (id, emb) in &entries {
        h.update(id);
        h.update(&hash_tag(b"EMB", emb));
    }
    let _ = h.finalize();
    let commit_us = t0.elapsed().as_secs_f64() * 1e6;
    let t1 = Instant::now();
    let mut best = entries[0].0;
    let mut best_d = i64::MAX;
    for (id, emb) in &entries {
        let d: i64 = query
            .iter()
            .zip(emb.iter())
            .map(|(&a, &b)| {
                let x = i64::from(a) - i64::from(b);
                x * x
            })
            .sum();
        if d < best_d {
            best_d = d;
            best = *id;
        }
    }
    let _ = best;
    (commit_us, t1.elapsed().as_secs_f64() * 1e6)
}
fn hash_tag(tag: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(tag);
    h.update(payload);
    *h.finalize().as_bytes()
}
fn bench_embedding(i: usize, dim: u32) -> Vec<u8> {
    let mut out = Vec::new();
    for d in 0..dim {
        let mixed = (i as u64)
            .wrapping_mul(0x9E37_79B9)
            .wrapping_add(u64::from(d));
        out.extend_from_slice(&((((mixed >> 17) % 2048) as i16) - 1024).to_le_bytes());
    }
    out
}
