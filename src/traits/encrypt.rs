use std::num::NonZeroU32;


use crate::{
    error::Error, 
    encrypted::Encrypted, 
    key_salt_pair::KeySaltPair, 
    traits::encryption_algorithm::EncryptionAlgorithm, 
};

/// 
pub trait Encrypt: Sized {
    type Error: From<Error>;
    type AlgorithmType: EncryptionAlgorithm;

    /// Number of hashing rounds when creating a key from the provided secret
    /// Default value equals a medium secure key
    const KEY_ITERATIONS: NonZeroU32 = NonZeroU32::new(600000).unwrap();

    /// Should return the data you wish to encrypt in your type
    fn data_to_encrypt(&self) -> Result<impl Into<Vec<u8>>, Self::Error>;

    fn from_decrypted_data(data: &[u8]) -> Result<Self, Self::Error>;

    /// Encrypts data supplied from this type and wraps it in an [Encrypted<T>]
    /// This method will create a new [Key] and can stall for a significant amount of time
    /// depending on the number of key iterations(hashing rounds) are set
    fn encrypt(&self, secret: &str) -> Result<Encrypted<Self>, Self::Error> {
        Encrypted::encrypt(KeySaltPair::new(secret)?, self.data_to_encrypt()?.into())
    }

    fn encrypt_with_key_and_salt(&self, key_salt_pair: KeySaltPair<Self>) -> Result<Encrypted<Self>, Self::Error> {
        Encrypted::encrypt(key_salt_pair, self.data_to_encrypt()?.into())
    }
} 