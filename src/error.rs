use thiserror::Error;


#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to create random value for Salt)")]
    FailedToCreateSalt,
    #[error("Failed to create random value for Nonce")]
    FailedToCreateNonce,
    #[error("Key length did not match required algorithm key length, expected: {expected}, found: {actual}")]
    WrongKeyLength{expected: usize, actual: usize},
    #[error("Failed to encrypt data")]
    FailedToEncryptData,
    #[error("Failed to decrypt data")]
    FailedToDecryptData,
}

