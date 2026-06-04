//! Phase III external-action binding (P3-1). Gated by `phase_iii_bind` feature.

use crate::Store;
use mneme_cap::Capability;
use mneme_core::{ActionReceipt, MnemeError};
use mneme_crypto::KeyPair;

impl Store {
    /// Bind an external action to the current signed root and authorizing capability.
    ///
    /// Fail-closed when `phase_iii_bind` is disabled on this crate (default).
    pub fn bind_external_action(
        &self,
        action_commit: [u8; 32],
        cap: &Capability,
        sanctioner_signer: &KeyPair,
        cognition_cert_commit: Option<[u8; 32]>,
    ) -> Result<ActionReceipt, MnemeError> {
        self.verify_cap(cap)?;
        let root = self.current_root()?;
        mneme_account::bind_action(
            action_commit,
            cap.inner(),
            sanctioner_signer,
            &root,
            cognition_cert_commit,
        )
    }
}
