//! Byte-deterministic prompt assembly from verified recall entries (Phase II P2-3).
//!
//! **Untrusted component:** the Context Gate checks `context_hash == certified_memory_set_hash`
//! binding via the CCA; a buggy assembler cannot smuggle context past hash equality.
//!
//! **Honesty:** assembly proves *which authenticated entries* were concatenated into the prompt —
//! not semantic truth, not output correctness (see `docs/ROADMAP.md` Phase II).

#![forbid(unsafe_code)]
#![deny(warnings)]

mod assembly;

pub use assembly::{
    ASSEMBLY_PROFILE_V1, AssemblyOutcome, assemble_verified_context, certified_memory_set_payload,
    encode_assembled_prompt_v1,
};

#[cfg(test)]
mod profile_id_tests {
    use super::ASSEMBLY_PROFILE_V1;
    use blake3;

    #[test]
    fn profile_v1_id_is_frozen() {
        assert_eq!(
            ASSEMBLY_PROFILE_V1.id,
            *blake3::hash(b"MNEME-ASM-PROFILE-v1\x00").as_bytes()
        );
    }
}
