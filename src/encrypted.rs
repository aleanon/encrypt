use std::marker::PhantomData;

use ring::{aead::{Aad, BoundKey, Nonce, OpeningKey, UnboundKey}, hkdf::KeyType};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::encrypted_nonce_sequence::EncryptedNonceSequence;

use super::{error::Error, traits::encrypt::Encrypt, key_salt_pair::KeySaltPair, salt::Salt, traits::encryption_algorithm::EncryptionAlgorithm, traits::key::Key};



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

        let nonce_sequence = EncryptedNonceSequence::new()
            .map_err(|_| Error::FailedToCreateNonce)?;

        let nonce_bytes = nonce_sequence.get_current_as_bytes();

        let unbound_key = UnboundKey::new( Algo::<T>::ALGORITHM_TYPE, key_salt_pair.key().as_bytes())
            .map_err(|_| Error::WrongKeyLength { expected: Algo::<T>::ALGORITHM_TYPE.key_len(), actual: key_salt_pair.key().as_bytes().len() })?;

        let mut sealing_key = ring::aead::SealingKey::new(unbound_key, nonce_sequence);

        sealing_key
            .seal_in_place_append_tag(Aad::empty(), &mut data)
            .map_err(|_| Error::FailedToEncryptData)?;

        Ok(Self {
            data,
            salt: key_salt_pair.into_salt(),
            nonce_bytes,
            _marker: PhantomData,
        })
    }

    pub fn decrypt(&self, secret: &str) -> Result<T, T::Error> {
        let encryption_key = KeyKind::<T>::create_key(T::KEY_ITERATIONS, secret.as_bytes(), &self.salt);
        let algorithm = Algo::<T>::ALGORITHM_TYPE;
        let unbound_key = UnboundKey::new(algorithm, encryption_key.as_bytes())
            .map_err(|_| Error::WrongKeyLength { expected: algorithm.len(), actual: encryption_key.as_bytes().len() })?;

        let nonce_sequence = EncryptedNonceSequence::with_nonce(&Nonce::assume_unique_for_key(
            self.nonce_bytes.clone(),
        ));
        let mut opening_key = OpeningKey::new(unbound_key, nonce_sequence);
        
        let mut data = self.data.clone();

        let decrypted = opening_key
            .open_in_place(Aad::empty(), &mut data)
            .map_err(|_| Error::FailedToDecryptData)?;

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




// #[cfg(test)]
// mod tests {
//     use std::{num::NonZeroU32, str::Utf8Error};

//     use bip39::{ErrorKind, Language, Mnemonic};

//     use crate::crypto::encryption::traits::encryption_algorithm::AES256GCM;

//     use super::*;

//     #[derive(Debug, Error)]
// pub enum MyError {
//     #[error("Failed to parse decrypted data")]
//     InvalidPhraseForMnemonic(#[from] ErrorKind),
//     #[error("Invalid utf-8 in decrypted data")]
//     InvalidUtf8InDecryptedData(#[from] Utf8Error),
//     #[error("Encrypt Error: {0}")]
//     EncryptError(#[from] CryptoError)
// }



// impl Encrypt for Mnemonic {
//     type Error = MyError;
//     type AlgorithmType = AES256GCM;    
//     const KEY_ITERATIONS: NonZeroU32 = NonZeroU32::new(1000).unwrap();

//     fn data_to_encrypt(&self) -> Result<impl Into<Vec<u8>>, Self::Error> {
//         Ok(self.phrase())
//     }

//     fn from_decrypted_data(data: &[u8]) -> Result<Self, Self::Error> {
//         Ok(Mnemonic::from_phrase(std::str::from_utf8(data)?, bip39::Language::English)?)
//     }

// }

//     #[test]
//     fn test_encryption_decryption() {
//         let phrase = "toward point obtain quit degree route beauty magnet hidden cereal reform increase limb measure guide skirt nominee faint shoulder win deal april error axis";
//         let mnemonic = Mnemonic::from_phrase(
//             phrase,
//             Language::English
//         ).expect("Failed to create mnemonic");

//         let secret = "password123";
//         let encrypted = mnemonic.encrypt(secret).expect("Failed to encrypt mnemonic");

//         if let Ok(string) = std::str::from_utf8(encrypted.encrypted_data()) {
//             assert_ne!(string, phrase)
//         }

//         let decrypted = encrypted.decrypt(secret).expect("Failed to decrypt mnemonic");
//         assert_eq!(mnemonic.phrase(), decrypted.phrase());
//     }
// }