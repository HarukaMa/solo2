//! Constants.

use trussed::types::{CertId, KeyId};

#[cfg(not(feature = "fast-button-timeout"))]
pub const FIDO2_UP_TIMEOUT: u32 = 30_000;
#[cfg(feature = "fast-button-timeout")]
pub const FIDO2_UP_TIMEOUT: u32 = 5_000;
pub const U2F_UP_TIMEOUT: u32 = 250;

pub const ATTESTATION_CERT_ID: CertId = CertId::from_special(0);
pub const ATTESTATION_KEY_ID: KeyId = KeyId::from_special(0);
