use mneme_core::FixedPointEmbedding;
use rand::Rng;

fn reference_l2_checked(a: &[i16], b: &[i16]) -> Option<i64> {
    let mut sum = 0i64;
    for (x, y) in a.iter().zip(b) {
        let diff = i64::from(*x) - i64::from(*y);
        let diff_sq = diff.checked_mul(diff)?;
        sum = sum.checked_add(diff_sq)?;
    }
    Some(sum)
}

fn reference_dot_checked(a: &[i16], b: &[i16]) -> Option<i64> {
    let mut sum = 0i64;
    for (x, y) in a.iter().zip(b) {
        let term = i64::from(*x).checked_mul(i64::from(*y))?;
        sum = sum.checked_add(term)?;
    }
    Some(sum)
}

#[test]
fn test_differential_distance_oracle() {
    let mut rng = rand::thread_rng();
    for _ in 0..2500 {
        let dim: u32 = rng.gen_range(1..=128);
        let scale: i8 = rng.gen_range(-10..=10);
        let mut comps1 = Vec::with_capacity(dim as usize);
        let mut comps2 = Vec::with_capacity(dim as usize);

        // Mix of normal and overflow-inducing values
        let range_limit = if rng.gen_bool(0.1) {
            // High chance of overflow
            32767
        } else {
            // Normal values
            2000
        };

        for _ in 0..dim {
            comps1.push(rng.gen_range(-range_limit..=range_limit));
            comps2.push(rng.gen_range(-range_limit..=range_limit));
        }

        let emb1 = FixedPointEmbedding::new(dim, scale, comps1).unwrap();
        let emb2 = FixedPointEmbedding::new(dim, scale, comps2).unwrap();

        let l2_res = emb1.squared_l2_distance(&emb2);
        let ref_l2 = reference_l2_checked(&emb1.components, &emb2.components);
        match (l2_res, ref_l2) {
            (Ok(actual), Some(expected)) => {
                assert_eq!(actual, expected, "Squared L2 mismatch");
            }
            (Err(_), None) => {}
            (res, expected) => {
                panic!(
                    "Squared L2 outcome mismatch on dim={dim}, range={range_limit}: actual={res:?}, expected={expected:?}"
                );
            }
        }

        let dot_res = emb1.dot_product(&emb2);
        let ref_dot = reference_dot_checked(&emb1.components, &emb2.components);
        match (dot_res, ref_dot) {
            (Ok(actual), Some(expected)) => {
                assert_eq!(actual, expected, "Dot product mismatch");
            }
            (Err(_), None) => {}
            (res, expected) => {
                panic!(
                    "Dot product outcome mismatch on dim={dim}, range={range_limit}: actual={res:?}, expected={expected:?}"
                );
            }
        }
    }
}
