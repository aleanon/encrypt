use super::{salt::Salt, traits::encrypt::Encrypt, traits::encryption_algorithm::EncryptionAlgorithm, traits::key::Key};


#[allow(type_alias_bounds)]
pub type KeyType<T> where T: Encrypt = <T::AlgorithmType as EncryptionAlgorithm>::KeyType;

pub struct KeySaltPair<T: Encrypt> {
    key: KeyType<T>,
    salt: Salt,
}

impl<T> KeySaltPair<T> where
    T: Encrypt,
{
    
    pub fn new<U: AsRef<[u8]>>(source: U) -> Result<Self, crate::Error> {
        let salt = Salt::new().map_err(|_|crate::Error::FailedToCreateSalt)?;
        let key= KeyType::<T>::create_key(T::KEY_ITERATIONS, source, &salt);
        Ok(Self { key, salt})
    }

    pub fn with_salt(source: impl AsRef<[u8]>, salt: Salt) -> Self {
        Self {
            key: KeyType::<T>::create_key(T::KEY_ITERATIONS, source.as_ref(), &salt),
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

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use crate::algorithms::AES256GCM;
    use super::*;

    // Test implementation
    struct TestType;
    impl Encrypt for TestType {
        type Error = crate::Error;
        type AlgorithmType = AES256GCM;
        const KEY_ITERATIONS: NonZeroU32 = NonZeroU32::new(1000).unwrap();

        fn data_to_encrypt(&self) -> Result<impl Into<Vec<u8>>, Self::Error> {
            Ok(vec![])
        }

        fn from_decrypted_data(_data: &[u8]) -> Result<Self, Self::Error> {
            Ok(TestType)
        }
    }

    #[test]
    fn test_key_salt_pair_creation() {
        let pair = KeySaltPair::<TestType>::new("test_secret").expect("Failed to create key-salt pair");
        assert!(!pair.salt().as_bytes().is_empty());
    }

    #[test]
    fn test_from_existing_salt() {
        let salt = Salt::new().expect("Failed to create salt");
        let pair = KeySaltPair::<TestType>::with_salt("test_secret", salt.clone());
        assert_eq!(pair.salt().as_bytes(), salt.as_bytes());
    }

    #[test]
    fn test_into_inner() {
        let pair = KeySaltPair::<TestType>::new("test_secret").expect("Failed to create key-salt pair");
        let original_key_bytes = pair.key().as_bytes().to_vec();
        let original_salt_bytes = pair.salt().as_bytes().to_vec();
        
        let (key, salt) = pair.into_inner();
        assert_eq!(key.as_bytes(), original_key_bytes);
        assert_eq!(salt.as_bytes(), original_salt_bytes);
    }

    #[test]
    fn test_take_operations() {
        let mut pair = KeySaltPair::<TestType>::new("test_secret").expect("Failed to create key-salt pair");
        let original_key_bytes = pair.key().as_bytes().to_vec();
        let original_salt_bytes = pair.salt().as_bytes().to_vec();

        let taken_salt = pair.take_salt();
        assert_eq!(taken_salt.as_bytes(), original_salt_bytes);
        assert_eq!(pair.salt().as_bytes(), &[0u8; Salt::LENGTH]);

        let taken_key = pair.take_key();
        assert_eq!(taken_key.as_bytes(), original_key_bytes);
    }

    #[test]
    fn test_same_secret_different_instances() {
        let pair = KeySaltPair::<TestType>::new("test_secret").expect("Failed to create key-salt pair");
        let (original_key_bytes, original_salt_bytes) = pair.into_inner();

        let pair2 = KeySaltPair::<TestType>::new("test_secret").expect("Failed to create key-salt pair");
        let (key, salt) = pair2.into_inner();

        assert_ne!(salt.as_bytes(), original_salt_bytes.as_bytes());
        assert_ne!(key.as_bytes(), original_key_bytes.as_bytes());
    }

    #[test]
    fn test_different_secrets_same_salt() {
        let salt = Salt::new().expect("Failed to create salt");
        let pair1 = KeySaltPair::<TestType>::with_salt("secret1", salt.clone());
        let pair2 = KeySaltPair::<TestType>::with_salt("secret2", salt);

        assert_eq!(pair1.salt().as_bytes(), pair2.salt().as_bytes());
        assert_ne!(pair1.key().as_bytes(), pair2.key().as_bytes());
    }

    #[test]
    fn test_same_secret_same_salt() {
        let salt = Salt::new().expect("Failed to create salt");
        let pair1 = KeySaltPair::<TestType>::with_salt("secret", salt.clone());
        let pair2 = KeySaltPair::<TestType>::with_salt("secret", salt);

        assert_eq!(pair1.salt().as_bytes(), pair2.salt().as_bytes());
        assert_eq!(pair1.key().as_bytes(), pair2.key().as_bytes());
    }
}
