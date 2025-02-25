
use super::{salt::Salt, error::CryptoError, traits::encrypt::Encrypt, traits::encryption_algorithm::EncryptionAlgorithm, traits::key::Key};


#[allow(type_alias_bounds)]
pub type KeyType<T> where T: Encrypt = <T::AlgorithmType as EncryptionAlgorithm>::KeyType;

pub struct KeySaltPair<T: Encrypt> {
    key: KeyType<T>,
    salt: Salt,
}

impl<T> KeySaltPair<T> where 
    T: Encrypt,
{
    
    pub fn new<U: AsRef<[u8]>>(source: U) -> Result<Self, CryptoError> {
        let salt = Salt::new().map_err(|_|CryptoError::FailedToCreateSalt)?;
        let key= KeyType::<T>::create_key(T::KEY_ITERATIONS, source, &salt);
        Ok(Self { key, salt})
    }

    pub fn from_salt(source: &str, salt: Salt) -> Self {
        Self {
            key: KeyType::<T>::create_key(T::KEY_ITERATIONS, source.as_bytes(), &salt),
            salt: salt,
        }
    }

    pub fn key(&self) -> &KeyType<T> {
        &self.key
    }

    pub fn salt(&self) -> &Salt {
        &self.salt
    }

    /// Takes the [Key] and [Salt], dropping the empty [KeyAndSalt] 
    pub fn into_inner(mut self) -> (KeyType<T>, Salt) {
        (std::mem::take(&mut self.key), std::mem::take(&mut self.salt))
    }

    /// Takes the [Salt], dropping the [Key]
    pub fn into_salt(mut self) -> Salt {
        std::mem::take(&mut self.salt)
    }

    /// Takes the [Key], dropping the [Salt]
    pub fn into_key(mut self) -> KeyType<T> {
        std::mem::take(&mut self.key)
    }

    /// Takes the [Salt], leaving the [Key]
    pub fn take_salt(&mut self) -> Salt {
        std::mem::take(&mut self.salt)
    }

    /// Takes the [Key], leaving the [Salt]
    pub fn take_key(&mut self) -> KeyType<T> {
        std::mem::take(&mut self.key)
    }
}