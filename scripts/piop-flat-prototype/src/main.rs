use piop_flat_prototype::PIOP_FLAT_HONESTY; use std::env;
fn main() {
  let v: usize = env::var("PIOP_FLAT_V").ok().and_then(|s| s.parse().ok()).unwrap_or(256);
  let dim: u32 = env::var("PIOP_FLAT_DIM").ok().and_then(|s| s.parse().ok()).unwrap_or(32);
  let (c,s) = piop_flat_prototype::run_microbench(v,dim);
  println!("piop_flat_honesty={PIOP_FLAT_HONESTY}"); println!("piop_flat_cardinality={v}"); println!("piop_flat_dim={dim}");
  println!("piop_flat_sidecar_commit_us={c:.3}"); println!("piop_flat_scan_us={s:.3}");
  println!("piop_prover_secs=NOT_MEASURED"); println!("piop_verifier_secs=NOT_MEASURED"); println!("piop_proof_bytes=NOT_MEASURED");
}
