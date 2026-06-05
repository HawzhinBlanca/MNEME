//! Deterministic pause hook for kill/resume tests (§17.3, INV-8).
//! Thread-local so parallel `cargo test` does not cross-contaminate boundaries.

use mneme_core::MnemeError;
use std::cell::Cell;

thread_local! {
    static PAUSE_AT: Cell<u8> = const { Cell::new(0) };
}

pub const AFTER_BEGIN_INCOMPLETE: u8 = 1;
pub const AFTER_OBJECT_WRITE: u8 = 2;
pub const AFTER_KEY_INDEX: u8 = 3;
pub const AFTER_PERSIST_INDEX: u8 = 4;
pub const AFTER_APPEND_CHECKPOINT: u8 = 5;
pub const AFTER_WRITE_HEAD: u8 = 6;
pub const BEFORE_COMMIT_INCOMPLETE: u8 = 7;

#[cfg(feature = "internal_test_support")]
pub fn test_set_pause_at(stage: u8) {
    PAUSE_AT.with(|p| p.set(stage));
}

#[cfg(feature = "internal_test_support")]
pub fn test_clear_pause() {
    PAUSE_AT.with(|p| p.set(0));
}

pub fn checkpoint(stage: u8) -> Result<(), MnemeError> {
    let hit = PAUSE_AT.with(|p| p.get() == stage);
    if hit {
        return Err(MnemeError::IncompleteTransaction);
    }
    Ok(())
}
