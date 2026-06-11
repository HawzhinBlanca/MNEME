use mneme_core::ObjectId;
use mneme_index::{
    CONTEXT_SET_LOCK_HONESTY, CONTEXT_SET_LOCK_PROOF_LEN, CONTEXT_SET_LOCK_STATUS,
    ContextSetLockProof, decode_context_set_lock_sidecar, encode_context_set_lock_sidecar,
    prove_context_set_lock, verify_context_set_lock,
};
fn oid(b: u8) -> ObjectId {
    ObjectId([b; 32])
}
#[test]
fn honesty_exports_are_scaffold_only() {
    assert!(CONTEXT_SET_LOCK_STATUS.contains("SCAFFOLD"));
    assert!(CONTEXT_SET_LOCK_HONESTY.contains("not semantic truth"));
}
#[test]
fn honest_proof_roundtrip_over_multiset() {
    let e = vec![oid(1), oid(2), oid(3)];
    let p = prove_context_set_lock(&e).unwrap();
    assert_eq!(p.proof_bytes.len(), CONTEXT_SET_LOCK_PROOF_LEN);
    verify_context_set_lock(&p, &e).unwrap();
}
#[test]
fn substituted_context_commit_fails_closed() {
    let e = vec![oid(5), oid(6)];
    let mut p = prove_context_set_lock(&e).unwrap();
    p.context_commit[31] ^= 1;
    assert!(verify_context_set_lock(&p, &e).is_err());
}
#[test]
fn truncated_entry_multiset_fails_closed() {
    let e = vec![oid(7), oid(8), oid(9)];
    let p = prove_context_set_lock(&e).unwrap();
    assert!(verify_context_set_lock(&p, &[oid(7)]).is_err());
}
#[test]
fn spliced_sidecar_wire_fails_closed() {
    let p = prove_context_set_lock(&[oid(0x42)]).unwrap();
    let mut w = encode_context_set_lock_sidecar(&p).unwrap();
    w.extend_from_slice(&[0xDE, 0xAD]);
    assert!(decode_context_set_lock_sidecar(&w).is_err());
}
#[test]
fn truncated_sidecar_wire_fails_closed() {
    let p = prove_context_set_lock(&[oid(0x43), oid(0x44)]).unwrap();
    let w = encode_context_set_lock_sidecar(&p).unwrap();
    assert!(decode_context_set_lock_sidecar(&w[..w.len() - 6]).is_err());
}
#[test]
fn empty_entry_set_fails_closed() {
    assert!(prove_context_set_lock(&[]).is_err());
}
#[test]
fn sidecar_decode_then_verify() {
    let e = vec![oid(0x10), oid(0x11)];
    let p = prove_context_set_lock(&e).unwrap();
    let d: ContextSetLockProof =
        decode_context_set_lock_sidecar(&encode_context_set_lock_sidecar(&p).unwrap()).unwrap();
    verify_context_set_lock(&d, &e).unwrap();
}
