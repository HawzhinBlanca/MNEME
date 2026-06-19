#![allow(unexpected_cfgs)]

#[cfg(kani)]
#[kani::proof]
#[kani::unwind(17)]
fn proof_distance_no_panic() {
    let dim = 16;
    let scale = 0;

    // Create symbolic components
    let mut comps1 = Vec::with_capacity(dim);
    let mut comps2 = Vec::with_capacity(dim);
    for _ in 0..dim {
        comps1.push(kani::any::<i16>());
        comps2.push(kani::any::<i16>());
    }

    let emb1 = mneme_core::FixedPointEmbedding::new(dim as u32, scale, comps1).unwrap();
    let emb2 = mneme_core::FixedPointEmbedding::new(dim as u32, scale, comps2).unwrap();

    // Call distance calculations. Since they use checked arithmetic, they must
    // either return Ok or Err, and never panic under any possible i16 input combination.
    let _l2 = emb1.squared_l2_distance(&emb2);
    let _dot = emb1.dot_product(&emb2);
}
