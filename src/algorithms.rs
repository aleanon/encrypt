use ring::aead::{Aad, Algorithm, BoundKey, OpeningKey, UnboundKey};

use crate::{keys::{Key128Bit, Key256Bit}, nonce_sequence::NonceSequence, traits::{encryption_algorithm::EncryptionAlgorithm, key::Key}, CryptoError};

pub struct AES128GCM;

impl EncryptionAlgorithm for AES128GCM {
    const ALGORITHM_TYPE: &'static Algorithm = &ring::aead::AES_128_GCM;
    type KeyType = Key128Bit;

    fn encrypt(data: &mut Vec<u8>, key: &impl Key, nonce_sequence: NonceSequence) -> Result<(), CryptoError> {
        encrypt_with_ring(data, key, Self::ALGORITHM_TYPE, nonce_sequence)
    }

    fn decrypt<'a>(data: &'a mut [u8], key: &impl Key, nonce_sequence: NonceSequence) -> Result<&'a [u8], CryptoError> {
        decrypt_with_ring(data, key, Self::ALGORITHM_TYPE, nonce_sequence)
    }
}

pub struct AES256GCM;

impl EncryptionAlgorithm for AES256GCM {
    const ALGORITHM_TYPE: &'static Algorithm = &ring::aead::AES_256_GCM;
    type KeyType = Key256Bit;

    fn encrypt(data: &mut Vec<u8>, key: &impl Key, nonce_sequence: NonceSequence) -> Result<(), CryptoError> {
        encrypt_with_ring(data, key, Self::ALGORITHM_TYPE, nonce_sequence)
    }

    fn decrypt<'a>(data: &'a mut [u8], key: &impl Key, nonce_sequence: NonceSequence) -> Result<&'a [u8], CryptoError> {
        decrypt_with_ring(data, key, Self::ALGORITHM_TYPE, nonce_sequence)
    }
}
pub struct CHACHA20POLY1305;

impl EncryptionAlgorithm for CHACHA20POLY1305 {
    const ALGORITHM_TYPE: &'static Algorithm = &ring::aead::CHACHA20_POLY1305;
    type KeyType = Key256Bit;

    fn encrypt(data: &mut Vec<u8>, key: &impl Key, nonce_sequence: NonceSequence) -> Result<(), CryptoError> {
        encrypt_with_ring(data, key, Self::ALGORITHM_TYPE, nonce_sequence)
    }

    fn decrypt<'a>(data: &'a mut [u8], key: &impl Key, nonce_sequence: NonceSequence) -> Result<&'a [u8], CryptoError> {
        decrypt_with_ring(data, key, Self::ALGORITHM_TYPE, nonce_sequence)
    }
}


fn encrypt_with_ring(data: &mut Vec<u8>, key: &impl Key, algorithm: &'static Algorithm, nonce_sequence: NonceSequence) -> Result<(), CryptoError> {
    let unbound_key = UnboundKey::new( algorithm, key.as_bytes())
        .map_err(|_| CryptoError::WrongKeyLength { expected: algorithm.key_len(), actual: key.as_bytes().len() })?;

    let mut sealing_key = ring::aead::SealingKey::new(unbound_key, nonce_sequence);

    sealing_key
        .seal_in_place_append_tag(Aad::empty(), data)
        .map_err(|_| CryptoError::FailedToEncryptData)?;

    Ok(())
}

fn decrypt_with_ring<'a>(data: &'a mut [u8], key: &impl Key, algorithm: &'static Algorithm, nonce_sequence: NonceSequence) -> Result<&'a [u8], CryptoError> {
    let unbound_key = UnboundKey::new(algorithm, key.as_bytes())
        .map_err(|_| CryptoError::WrongKeyLength { expected: algorithm.key_len(), actual: key.as_bytes().len() })?;

    let mut opening_key = OpeningKey::new(unbound_key, nonce_sequence);
    
    let decrypted = opening_key
        .open_in_place(Aad::empty(), data)
        .map_err(|_| CryptoError::FailedToDecryptData)?;

    Ok(decrypted)
}