use std::fmt::Display;


#[derive(Debug)]
pub enum CryptoError {
    FailedToCreateSalt,
    FailedToCreateNonce,
    WrongKeyLength{expected: usize, actual: usize},
    FailedToEncryptData,
    FailedToDecryptData,
}


impl std::error::Error for CryptoError {}

impl Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::FailedToCreateSalt => write!(f, "Failed to create random value for Salt"),
            CryptoError::FailedToCreateNonce => write!(f, "Failed to create random value for Nonce"),
            CryptoError::WrongKeyLength{expected, actual} => write!(f, "Key length did not match required algorithm key length, expected: {}, found: {}", expected, actual),
            CryptoError::FailedToEncryptData => write!(f, "Failed to encrypt data"),
            CryptoError::FailedToDecryptData => write!(f, "Failed to decrypt data"),
        }
    }
}

