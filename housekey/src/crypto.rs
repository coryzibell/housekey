pub mod keys;
pub mod session;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("decryption failed — invalid auth tag or corrupted data")]
    DecryptionFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("key derivation failed")]
    KeyDerivationFailed,
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    #[error("signature verification failed")]
    SignatureVerificationFailed,
}
