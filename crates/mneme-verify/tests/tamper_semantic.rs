//! Semantic index / ADS VO tamper cases (§17.2).

mod helpers;

use helpers::{SemanticFixture, build_valid_semantic_recall, sample_procedure};
use mneme_core::MnemeError;
use mneme_verify::verify_semantic_receipt;

macro_rules! sem_tamper {
    ($name:ident, |$f:ident| $body:stmt, $expected:expr) => {
        #[test]
        fn $name() {
            let mut fixture = build_valid_semantic_recall();
            {
                let $f = &mut fixture;
                $body
            }
            let err = run_semantic(&fixture).unwrap_err();
            assert_eq!(err, $expected, "case {}", stringify!($name));
        }
    };
}

fn run_semantic(f: &SemanticFixture) -> Result<(), MnemeError> {
    verify_semantic_receipt(
        &f.receipt,
        &f.root,
        &f.procedure,
        &f.trust,
        f.previous_root.as_ref(),
    )
}

// --- semantic receipt fields ---

sem_tamper!(
    sem_receipt_root_bound,
    |f| f.receipt.root_bound[0] ^= 0x01,
    MnemeError::ReceiptRootMismatch
);
sem_tamper!(
    sem_receipt_semantic_commit,
    |f| f.receipt.semantic_commit[31] ^= 0x80,
    MnemeError::ReceiptRootMismatch
);
sem_tamper!(
    sem_receipt_procedure_id,
    |f| f.receipt.verification_object.procedure_id[0] ^= 0x02,
    MnemeError::ProcedureMismatch
);
sem_tamper!(
    sem_receipt_procedure_id_byte_1,
    |f| f.receipt.verification_object.procedure_id[1] ^= 0x04,
    MnemeError::ProcedureMismatch
);
sem_tamper!(
    sem_receipt_procedure_id_byte_8,
    |f| f.receipt.verification_object.procedure_id[8] ^= 0x08,
    MnemeError::ProcedureMismatch
);
sem_tamper!(
    sem_receipt_procedure_id_byte_16,
    |f| f.receipt.verification_object.procedure_id[16] ^= 0x10,
    MnemeError::ProcedureMismatch
);
sem_tamper!(
    sem_receipt_procedure_id_byte_31,
    |f| f.receipt.verification_object.procedure_id[31] ^= 0x20,
    MnemeError::ProcedureMismatch
);
sem_tamper!(
    sem_receipt_query_commit,
    |f| {
        f.receipt
            .verification_object
            .result_ids
            .push(mneme_core::ObjectId([0xee; 32]));
    },
    MnemeError::ProcedureMismatch
);
sem_tamper!(
    sem_receipt_result_id_0,
    |f| f.receipt.verification_object.result_ids[0].0[0] ^= 0x08,
    MnemeError::ProcedureMismatch
);
sem_tamper!(
    sem_receipt_result_id_last,
    |f| {
        let last = f.receipt.verification_object.result_ids.len() - 1;
        f.receipt.verification_object.result_ids[last].0[31] ^= 0x10;
    },
    MnemeError::ProcedureMismatch
);

// --- semantic index node commits ---

sem_tamper!(
    sem_node_commit_0,
    |f| f.receipt.verification_object.nodes[0].0[0] ^= 0x01,
    MnemeError::IndexPathInvalid
);
sem_tamper!(
    sem_node_commit_1,
    |f| {
        if f.receipt.verification_object.nodes.len() > 1 {
            f.receipt.verification_object.nodes[1].0[10] ^= 0x02;
        }
    },
    MnemeError::IndexPathInvalid
);
sem_tamper!(
    sem_node_commit_2,
    |f| {
        if f.receipt.verification_object.nodes.len() > 2 {
            f.receipt.verification_object.nodes[2].0[20] ^= 0x04;
        }
    },
    MnemeError::IndexPathInvalid
);
sem_tamper!(
    sem_node_commit_0_byte_15,
    |f| f.receipt.verification_object.nodes[0].0[15] ^= 0x08,
    MnemeError::IndexPathInvalid
);
sem_tamper!(
    sem_node_commit_0_byte_31,
    |f| f.receipt.verification_object.nodes[0].0[31] ^= 0x10,
    MnemeError::IndexPathInvalid
);
sem_tamper!(
    sem_node_commit_2_byte_5,
    |f| {
        if f.receipt.verification_object.nodes.len() > 2 {
            f.receipt.verification_object.nodes[2].0[5] ^= 0x20;
        }
    },
    MnemeError::IndexPathInvalid
);

// --- semantic Merkle paths (every element, immudb lesson) ---

sem_tamper!(
    sem_path_node0_depth0,
    |f| flip_sem_path(&mut f.receipt.verification_object.nodes[0].1, 0),
    MnemeError::IndexPathInvalid
);
sem_tamper!(
    sem_path_node0_depth1,
    |f| flip_sem_path(&mut f.receipt.verification_object.nodes[0].1, 1),
    MnemeError::IndexPathInvalid
);
sem_tamper!(
    sem_path_node1_depth0,
    |f| {
        if f.receipt.verification_object.nodes.len() > 1 {
            flip_sem_path(&mut f.receipt.verification_object.nodes[1].1, 0);
        }
    },
    MnemeError::IndexPathInvalid
);
sem_tamper!(
    sem_path_node1_depth1,
    |f| {
        if f.receipt.verification_object.nodes.len() > 1 {
            flip_sem_path(&mut f.receipt.verification_object.nodes[1].1, 1);
        }
    },
    MnemeError::IndexPathInvalid
);
sem_tamper!(
    sem_path_truncated,
    |f| {
        f.receipt.verification_object.nodes[0].1.pop();
    },
    MnemeError::IndexPathInvalid
);
sem_tamper!(
    sem_path_extra_sibling,
    |f| f.receipt.verification_object.nodes[0].1.push([0xee; 32]),
    MnemeError::IndexPathInvalid
);
sem_tamper!(
    sem_candidate_second_embedding,
    |f| {
        if f.receipt.verification_object.candidates.len() > 1 {
            f.receipt.verification_object.candidates[1].1[0] ^= 0x01;
        }
    },
    MnemeError::IndexPathInvalid
);
sem_tamper!(
    sem_candidate_second_object_id,
    |f| {
        if f.receipt.verification_object.candidates.len() > 1 {
            f.receipt.verification_object.candidates[1].0.0[0] ^= 0x01;
        }
    },
    MnemeError::IndexPathInvalid
);
sem_tamper!(
    sem_node_commit_garbage,
    |f| f.receipt.verification_object.nodes[0].0 = [0xde; 32],
    MnemeError::IndexPathInvalid
);

// --- procedure / candidate tamper ---

sem_tamper!(
    sem_candidate_distance,
    |f| {
        if let Some((_, _, dist)) = f.receipt.verification_object.candidates.first_mut() {
            *dist = i64::MAX;
        }
    },
    MnemeError::ProcedureMismatch
);
sem_tamper!(
    sem_candidate_embedding_commit,
    |f| {
        if let Some((_, commit, _)) = f.receipt.verification_object.candidates.first_mut() {
            commit[0] ^= 0x01;
        }
    },
    MnemeError::IndexPathInvalid
);
sem_tamper!(
    sem_candidate_object_id,
    |f| {
        if let Some((id, _, _)) = f.receipt.verification_object.candidates.first_mut() {
            id.0[0] ^= 0x02;
        }
    },
    MnemeError::IndexPathInvalid
);
sem_tamper!(
    sem_wrong_procedure,
    |f| f.procedure.k = 99,
    MnemeError::ProcedureMismatch
);
sem_tamper!(
    sem_root_semantic_mismatch,
    |f| f.root.semantic_commit[0] ^= 0xff,
    MnemeError::RootSigInvalid
);

#[test]
fn sem_honesty_on_procedure_mismatch() {
    let mut f = build_valid_semantic_recall();
    f.receipt.verification_object.procedure_id[0] ^= 0x01;
    let err = run_semantic(&f).unwrap_err();
    assert_eq!(err, MnemeError::ProcedureMismatch);
    assert!(err.to_string().contains("not true nearest neighbors"));
}

#[test]
fn sem_valid_roundtrip() {
    let f = build_valid_semantic_recall();
    run_semantic(&f).expect("valid semantic receipt");
    assert_eq!(f.procedure, sample_procedure());
}

fn flip_sem_path(path: &mut [[u8; 32]], depth: usize) {
    if depth < path.len() {
        path[depth][0] ^= 0xff;
    }
}
