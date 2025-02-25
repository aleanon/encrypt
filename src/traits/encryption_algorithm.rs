use ring::aead::Algorithm;

use crate::{nonce_sequence::{self, NonceSequence}, traits::{encrypt::Encrypt, key::Key}, CryptoError};

pub trait EncryptionAlgorithm {
    const ALGORITHM_TYPE: &'static Algorithm;
    type KeyType: Key;

    fn encrypt(data: &mut Vec<u8>, key: &impl Key, nonce_sequence: NonceSequence) -> Result<(), CryptoError>;

    fn decrypt<'a>(data: &'a mut [u8], key: &impl Key, nonce_sequence: NonceSequence) -> Result<&'a [u8], CryptoError>;
}

