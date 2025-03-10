use std::num::NonZeroU32;


use crate::{
    encrypted::Encrypted, error::Error, key_salt_pair::KeySaltPair, traits::encryption_algorithm::EncryptionAlgorithm, Salt 
};

use super::Key;

/// A trait for types that can be encrypted and decrypted.
///
/// This trait provides functionality to encrypt data with a secret password, generating
/// a key-salt pair in the process. The encrypted data is wrapped in an `Encrypted<T>` type
/// which can later be decrypted back into the original type.
///
/// # Examples
///
/// ```
/// use std::num::NonZeroU32;
/// use encrypt::{traits::Encrypt, algorithms::AES256GCM};
///
/// // Define a type that we want to make encryptable
/// #[derive(Debug, PartialEq)]
/// struct SecretMessage(String);
///
///
/// // Implement the Encrypt trait
/// impl Encrypt for SecretMessage {
///     type Error = encrypt::Error;
///     type AlgorithmType = AES256GCM;
///     
///     // Optionally override KEY_ITERATIONS for faster/slower key derivation
///     const KEY_ITERATIONS: NonZeroU32 = NonZeroU32::new(1000).unwrap();
///
///     // Convert your type's data into bytes for encryption
///     fn data_to_encrypt(&self) -> Result<impl Into<Vec<u8>>, Self::Error> {
///         Ok(self.0.as_bytes().to_vec())
///     }
///
///     // Convert decrypted bytes back into your type
///     fn from_decrypted_data(data: &[u8]) -> Result<Self, Self::Error> {
///         Ok(Self(String::from_utf8(data.to_vec()).map_err(|_| encrypt::Error::FailedToParseDecryptedData)?))
///     }
/// }
///
/// // Example usage:
/// # fn main() -> Result<(), encrypt::Error> {
/// let message = SecretMessage("Hello, World!".to_string());
/// let password = "my-secure-password";
///
/// // Encrypt the message
/// let mut encrypted = message.encrypt_with_secret(password, [])?;
///
/// // Later, decrypt the message
/// let decrypted = encrypted.decrypt_with_secret(password, [])?;
/// assert_eq!(message, decrypted);
/// # Ok(())
/// # }
/// ```
///
/// # Security Considerations
///
/// - The `KEY_ITERATIONS` constant determines how many rounds of key derivation are performed.
///   Higher values are more secure but slower.
/// - The default encryption methods generate a new random salt for each encryption.
/// - You can reuse a key-salt pair for multiple encryptions using `encrypt_with_key_and_salt`.
/// - Using the 
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
    /// depending on the number of key iterations(hashing rounds) used
    fn encrypt_with_secret(&self, secret: impl AsRef<[u8]>, aad: impl AsRef<[u8]>) -> Result<Encrypted<Self>, Self::Error> {
        Encrypted::new(KeySaltPair::new(secret)?, self.data_to_encrypt()?.into(), aad)
    }

    fn encrypt_with_key_salt_pair(&self, key_salt_pair: KeySaltPair<Self>, aad: impl AsRef<[u8]>) -> Result<Encrypted<Self>, Self::Error> {
        Encrypted::new(key_salt_pair, self.data_to_encrypt()?.into(), aad)
    }

    fn encrypt_with_key(&self, key: &impl Key, aad: impl AsRef<[u8]>) -> Result<Encrypted<Self>, Self::Error> {
        Encrypted::new_without_salt(key, self.data_to_encrypt()?.into(), aad)
    }

    fn create_new_key_salt_pair(secret: impl AsRef<[u8]>) -> Result<KeySaltPair<Self>, Self::Error> {
        Ok(KeySaltPair::new(secret)?)
    }

    fn create_key_with_salt(secret: impl AsRef<[u8]>, salt: Salt) -> Result<KeySaltPair<Self>, Self::Error> {
        Ok(KeySaltPair::with_salt(secret, salt))
    }


    /// This is the fastest way to create a key, this key can not be recreated and must be saved for later use
    fn create_random_key() -> Result<impl Key, Self::Error> {
        Ok(<<Self::AlgorithmType as EncryptionAlgorithm>::KeyType as Key>::create_random_key()?)
    }
}
