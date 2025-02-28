use std::fmt::Display;


#[derive(Debug)]
pub enum Error {
    FailedToCreateSalt,
    FailedToCreateNonce,
    WrongKeyLength{expected: usize, actual: usize},
    FailedToEncryptData,
    FailedToDecryptData,
    FailedToGetDataForEncryption,
    FailedToParseDecryptedData,
}


impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::FailedToCreateSalt => write!(f, "Failed to create random value for Salt"),
            Error::FailedToCreateNonce => write!(f, "Failed to create random value for Nonce"),
            Error::WrongKeyLength{expected, actual} => write!(f, "Key length did not match required algorithm key length, expected: {}, found: {}", expected, actual),
            Error::FailedToEncryptData => write!(f, "Failed to encrypt data"),
            Error::FailedToDecryptData => write!(f, "Failed to decrypt data"),
            Error::FailedToGetDataForEncryption => write!(f, "Failed to get data for encryption"),
            Error::FailedToParseDecryptedData => write!(f, "Failed to parse decrypted data"),
        }
    }
}

