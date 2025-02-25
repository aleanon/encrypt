use std::marker::PhantomData;

use ring::aead::Nonce;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::nonce_sequence::NonceSequence;

use super::{error::CryptoError, traits::encrypt::Encrypt, key_salt_pair::KeySaltPair, salt::Salt, traits::encryption_algorithm::EncryptionAlgorithm, traits::key::Key};



#[allow(type_alias_bounds)]
type Algo<T> where T: Encrypt = T::AlgorithmType;
#[allow(type_alias_bounds)]
type KeyKind<T> where T: Encrypt = <T::AlgorithmType as EncryptionAlgorithm>::KeyType;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Encrypted<T: Encrypt> {
    data: Vec<u8>,
    salt: Salt,
    nonce_bytes: [u8; 12],
    _marker: PhantomData<T>
}

impl<T> Encrypted<T> 
    where 
        T: Encrypt,
    {
    
    pub(crate) fn encrypt(key_salt_pair: KeySaltPair<T>, mut data: Vec<u8>) -> Result<Self, T::Error> {

        let nonce_sequence = NonceSequence::new()
            .map_err(|_| CryptoError::FailedToCreateNonce)?;

        let nonce_bytes = nonce_sequence.get_current_as_bytes();

        Algo::<T>::encrypt(&mut data, key_salt_pair.key(), nonce_sequence)?;

        Ok(Self {
            data,
            salt: key_salt_pair.into_salt(),
            nonce_bytes,
            _marker: PhantomData,
        })
    }

    pub fn decrypt(&self, secret: impl AsRef<[u8]>) -> Result<T, T::Error> {
        let key = KeyKind::<T>::create_key(T::KEY_ITERATIONS, secret, &self.salt);

        let nonce_sequence = NonceSequence::with_nonce(&Nonce::assume_unique_for_key(
            self.nonce_bytes.clone(),
        ));
        
        let mut data = self.data.clone();

        let decrypted = Algo::<T>::decrypt(data.as_mut_slice(), &key, nonce_sequence)?;
 
        let result:T = T::from_decrypted_data(decrypted)?;

        data.zeroize();

        Ok(result)
    }

    pub fn salt(&self) -> &Salt {
        &self.salt
    }

    pub fn encrypted_data(&self) -> &[u8] {
        &self.data
    }
}




#[cfg(test)]
mod tests {
    use std::{num::NonZeroU32, string::FromUtf8Error};

    use thiserror::Error;

    use crate::algorithms::AES256GCM;

    use super::*;

    #[derive(Debug, Error)]
pub enum MyError {
    #[error("Invalid utf-8 in decrypted data")]
    InvalidUtf8InDecryptedData(#[from] FromUtf8Error),
    #[error("Encrypt Error: {0}")]
    EncryptError(#[from] CryptoError)
}



impl Encrypt for String {
    type Error = MyError;
    type AlgorithmType = AES256GCM;    
    const KEY_ITERATIONS: NonZeroU32 = NonZeroU32::new(1000).unwrap();

    fn data_to_encrypt(&self) -> Result<impl Into<Vec<u8>>, Self::Error> {
        Ok(self.as_bytes())
    }

    fn from_decrypted_data(data: &[u8]) -> Result<Self, Self::Error> {
        Ok(String::from_utf8(data.to_vec())?)
    }

}

    #[test]
    fn test_encryption_decryption() {
        let phrase = String::from("encrypt this");

        let secret = "password123";
        let encrypted = phrase.encrypt(secret).expect("Failed to encrypt mnemonic");


        if let Ok(cypher_text) = std::str::from_utf8(encrypted.encrypted_data()) {
            assert!(!cypher_text.contains(&phrase))
        }
        
        let decrypted = encrypted.decrypt(secret).expect("Failed to decrypt mnemonic");
        assert_eq!(phrase, decrypted);
    }
}