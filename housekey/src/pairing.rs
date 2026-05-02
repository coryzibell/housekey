pub mod pair_setup;
pub mod pair_verify;

use thiserror::Error;

use crate::tlv::{TlvMap, TlvType};

#[derive(Debug, Error)]
pub enum PairingError {
    #[error("accessory returned error: {0}")]
    AccessoryError(u8),
    #[error("invalid PIN format — expected NNN-NN-NNN")]
    InvalidPin,
    #[error("SRP authentication failed — wrong PIN?")]
    SrpAuthFailed,
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("unexpected pairing state: expected {expected}, got {got}")]
    UnexpectedState { expected: u8, got: u8 },
    #[error(transparent)]
    Crypto(#[from] super::crypto::CryptoError),
    #[error(transparent)]
    Tlv(#[from] super::tlv::TlvError),
    #[error(transparent)]
    Transport(#[from] super::transport::TransportError),
}

fn check_state(tlvs: &TlvMap, expected: u8) -> Result<(), PairingError> {
    let state = tlvs
        .get(&TlvType::State)
        .and_then(|v| v.first().copied())
        .unwrap_or(0);
    if state != expected {
        return Err(PairingError::UnexpectedState {
            expected,
            got: state,
        });
    }
    Ok(())
}

fn check_error(tlvs: &TlvMap) -> Result<(), PairingError> {
    if let Some(err) = tlvs.get(&TlvType::Error)
        && let Some(&code) = err.first()
    {
        return Err(PairingError::AccessoryError(code));
    }
    Ok(())
}
