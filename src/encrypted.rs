
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;


use super::{error::Error, traits::encrypt::Encrypt, key_salt_pair::KeySaltPair, salt::Salt, traits::encryption_algorithm::EncryptionAlgorithm, traits::key::Key};



#[allow(type_alias_bounds)]
type Algo<T> where T: Encrypt = T::AlgorithmType;
#[allow(type_alias_bounds)]
type KeyType<T> where T: Encrypt = <T::AlgorithmType as EncryptionAlgorithm>::KeyType;
#[allow(type_alias_bounds)]
type NonceBytes<T> where T: Encrypt = <T::AlgorithmType as EncryptionAlgorithm>::Nonce;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Encrypted<T: Encrypt> {
    data: Vec<u8>,
    salt: Option<Salt>,
    nonce_bytes: NonceBytes<T>,
}

impl<T> Encrypted<T> 
    where 
        T: Encrypt,
    {

    pub(crate) fn new(mut key_salt_pair: KeySaltPair<T>, data: Vec<u8>) -> Result<Self, T::Error> {
        let mut instance = Self {
            data,
            salt: Some(key_salt_pair.take_salt()),
            nonce_bytes: NonceBytes::<T>::default(),
        };

        instance.encrypt(key_salt_pair.key())?; 

        Ok(instance)
    }

    pub(crate) fn new_without_salt(key: &impl Key, data: Vec<u8>) -> Result<Self, T::Error> {
        let mut instance = Self {
            data,
            salt: None,
            nonce_bytes: NonceBytes::<T>::default(),
        };

        instance.encrypt(key)?;

        Ok(instance)
    }
    

    pub(crate) fn encrypt(&mut self, key: &impl Key) -> Result<(), T::Error> {
        let Ok(nonce_bytes) = Algo::<T>::encrypt(&mut self.data, key) else {
            self.data.zeroize();
            return Err(Error::FailedToEncryptData.into());
        };
        self.nonce_bytes = nonce_bytes;
        Ok(())
    }

    /// This method can be very slow, depending on the number of key iterations used when creating the key
    /// for fast decryption use the `decrypt_with_key()` method instead.
    pub fn decrypt_with_secret(&mut self, secret: impl AsRef<[u8]>) -> Result<T, T::Error> {
        let Some(salt) = &self.salt else {
            return Err(Error::FailedToDecryptData.into());
        };
        let key = KeyType::<T>::create_key(T::KEY_ITERATIONS, secret, salt);
        self.decrypt_with_key(&key)        
    }

    pub fn decrypt_with_key(&mut self, key: &impl Key) -> Result<T, T::Error> {        
        let (result, data_length) = {
            let decrypted = Algo::<T>::decrypt(self.data.as_mut_slice(), key, &self.nonce_bytes)?;
     
            let result = T::from_decrypted_data(decrypted)?;
            (result, decrypted.len())
        };
        
        self.data.truncate(data_length);
        self.encrypt(key)?;

        Ok(result)
    }

    pub fn salt(&self) -> Option<&Salt> {
        self.salt.as_ref()
    }

    pub fn encrypted_data(&self) -> &[u8] {
        &self.data
    }

}




#[cfg(test)]
mod tests {
    use std::{num::NonZeroU32, string::FromUtf8Error};
    use thiserror::Error;
    use crate::algorithms::{AES256GCM, CHACHA20POLY1305};
    use super::*;

    #[derive(Debug, Error)]
    pub enum MyError {
        #[error("Invalid utf-8 in decrypted data")]
        InvalidUtf8InDecryptedData(#[from] FromUtf8Error),
        #[error("Encrypt Error: {0}")]
        EncryptError(#[from] Error)
    }

    impl Encrypt for String {
        type Error = MyError;
        type AlgorithmType = CHACHA20POLY1305;    
        const KEY_ITERATIONS: NonZeroU32 = NonZeroU32::new(1).unwrap();

        fn data_to_encrypt(&self) -> Result<impl Into<Vec<u8>>, Self::Error> {
            Ok(self.as_bytes())
        }

        fn from_decrypted_data(data: &[u8]) -> Result<Self, Self::Error> {
            Ok(String::from_utf8(data.to_vec())?)
        }
    }

    impl Encrypt for Vec<u8> {
        type Error = Error;
        type AlgorithmType = AES256GCM;    
        const KEY_ITERATIONS: NonZeroU32 = NonZeroU32::new(1).unwrap();

        fn data_to_encrypt(&self) -> Result<impl Into<Vec<u8>>, Self::Error> {
            Ok(self.clone())
        }

        fn from_decrypted_data(data: &[u8]) -> Result<Self, Self::Error> {
            Ok(data.to_vec())
        }
    }

    #[test]
    fn test_basic_encryption_decryption() {
        let phrase = String::from("encrypt this");
        let secret = "password123";
        let mut encrypted = phrase.encrypt_with_secret(secret).expect("Failed to encrypt data");

        if let Ok(cypher_text) = std::str::from_utf8(encrypted.encrypted_data()) {
            assert!(!cypher_text.contains(&phrase))
        }
        
        let decrypted = encrypted.decrypt_with_secret(secret).expect("Failed to decrypt data");
        assert_eq!(phrase, decrypted);
    }

    #[test]
    fn test_empty_string() {
        let empty = String::new();
        let secret = "password123";
        let mut encrypted = empty.encrypt_with_secret(secret).expect("Failed to encrypt empty string");
        let decrypted = encrypted.decrypt_with_secret(secret).expect("Failed to decrypt empty string");
        assert_eq!(empty, decrypted);
    }

    #[test]
    fn test_binary_data() {
        let data = vec![1, 2, 3, 4, 5];
        let secret = "binary_secret";
        let mut encrypted = data.encrypt_with_secret(secret).expect("Failed to encrypt binary data");
        let decrypted = encrypted.decrypt_with_secret(secret).expect("Failed to decrypt binary data");
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_wrong_secret() {
        let phrase = String::from("sensitive data");
        let secret = "correct_password";
        let wrong_secret = "wrong_password";
        
        let mut encrypted = phrase.encrypt_with_secret(secret).expect("Failed to encrypt data");
        let result = encrypted.decrypt_with_secret(wrong_secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_encryption_state() {
        let phrase = String::from("test encryption state");
        let secret = "secret123";
        
        let mut encrypted = phrase.encrypt_with_secret(secret).expect("Failed to encrypt initially");
        let initial_encrypted_data = encrypted.encrypted_data().to_vec();
        
        let decrypted = encrypted.decrypt_with_secret(secret).expect("Failed to decrypt");
        assert_eq!(phrase, decrypted);
        
        assert_ne!(encrypted.encrypted_data(), phrase.as_bytes());
        
        assert_ne!(encrypted.encrypted_data(), &initial_encrypted_data);
    }

    #[test]
    fn test_salt_uniqueness() {
        let phrase = String::from("test salt");
        let secret = "password";
        
        let encrypted1 = phrase.encrypt_with_secret(secret).expect("Failed to encrypt first time");
        let encrypted2 = phrase.encrypt_with_secret(secret).expect("Failed to encrypt second time");
        
        assert_ne!(encrypted1.salt(), encrypted2.salt());
        
        assert_ne!(encrypted1.encrypted_data(), encrypted2.encrypted_data());
    }

    #[test]
    fn test_data_corruption() {
        let phrase = String::from("test corruption");
        let secret = "password";
        
        let mut encrypted = phrase.encrypt_with_secret(secret).expect("Failed to encrypt");
        
        let mut corrupted_data = encrypted.encrypted_data().to_vec();
        if let Some(byte) = corrupted_data.get_mut(0) {
            *byte = byte.wrapping_add(1);
        }
        
        encrypted.data = corrupted_data;
        
        assert!(encrypted.decrypt_with_secret(secret).is_err());
    }

    #[test]
    fn test_unicode_handling() {
        let phrase = String::from("Hello 🌍 World! 你好世界");
        let secret = "password123";
        
        let mut encrypted = phrase.encrypt_with_secret(secret).expect("Failed to encrypt unicode");
        let decrypted = encrypted.decrypt_with_secret(secret).expect("Failed to decrypt unicode");
        
        assert_eq!(phrase, decrypted);
    }

    #[test]
    fn test_multiple_decryption_recryption() {
        let phrase = String::from("encrypt this");
        let secret = "password123";
        let mut encrypted = phrase.encrypt_with_secret(secret).expect("Failed to encrypt data");        
        let _decrypted = encrypted.decrypt_with_secret(secret).expect("Failed to decrypt data");
        let _decrypted = encrypted.decrypt_with_secret(secret).unwrap();
        let decrypted = encrypted.decrypt_with_secret(secret).unwrap();
        assert_eq!(phrase, decrypted);
    }
}
