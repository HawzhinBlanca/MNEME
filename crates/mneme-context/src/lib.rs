//! Byte-deterministic prompt assembly from verified recall entries (Phase II P2-3).
//!
//! **Untrusted component:** the Context Gate independently checks the assembled-context
//! digest and certified-memory-set digest carried by the CCA. The two digests are
//! domain-separated and must not be compared for equality.
//!
//! **Honesty:** assembly proves *which authenticated entries* were concatenated into the prompt —
//! not semantic truth, not output correctness (see `docs/ROADMAP.md` Phase II).

#![forbid(unsafe_code)]
#![deny(warnings)]

mod assembly;

pub use assembly::{
    ASSEMBLY_PROFILE_V1, AssemblyOutcome, assemble_verified_context, certified_memory_set_payload,
    consumption_attestation_from_assembly, encode_assembled_prompt_v1,
    output_binding_from_assembly,
};

#[cfg(test)]
mod profile_id_tests {
    use super::ASSEMBLY_PROFILE_V1;

    #[test]
    fn profile_v1_id_is_frozen() {
        assert_eq!(
            ASSEMBLY_PROFILE_V1.id,
            *blake3::hash(b"MNEME-ASM-PROFILE-v1\x00").as_bytes()
        );
    }
}
