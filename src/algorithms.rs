use ring::aead::{Aad, Algorithm, BoundKey, Nonce, OpeningKey, UnboundKey, NONCE_LEN};

use crate::{keys::{Key128Bit, Key256Bit}, nonce_sequence::NonceSequence, traits::{encryption_algorithm::EncryptionAlgorithm, key::Key}, Error};

pub struct AES128GCM;

impl EncryptionAlgorithm for AES128GCM {
    type KeyType = Key128Bit;
    type Nonce = [u8; NONCE_LEN];

    fn encrypt(data: &mut Vec<u8>, key: &impl Key, aad: impl AsRef<[u8]>) -> Result<Self::Nonce, Error> {
        encrypt_with_ring(data, key, &ring::aead::AES_128_GCM, aad)
    }

    fn decrypt<'a>(data: &'a mut [u8], key: &impl Key, nonce: &Self::Nonce, aad: impl AsRef<[u8]>) -> Result<&'a [u8], Error> {
        decrypt_with_ring(data, key, &ring::aead::AES_128_GCM, nonce.to_owned(), aad)
    }
}

pub struct AES256GCM;

impl EncryptionAlgorithm for AES256GCM {
    type KeyType = Key256Bit;
    type Nonce = [u8; NONCE_LEN];

    fn encrypt(data: &mut Vec<u8>, key: &impl Key, aad: impl AsRef<[u8]>) -> Result<Self::Nonce, Error> {
        encrypt_with_ring(data, key, &ring::aead::AES_256_GCM, aad)
    }

    fn decrypt<'a>(data: &'a mut [u8], key: &impl Key, nonce: &Self::Nonce, aad: impl AsRef<[u8]>) -> Result<&'a [u8], Error> {
        decrypt_with_ring(data, key, &ring::aead::AES_256_GCM, nonce.to_owned(), aad)
    }
}

pub struct CHACHA20POLY1305;

impl EncryptionAlgorithm for CHACHA20POLY1305 {
    type KeyType = Key256Bit;
    type Nonce = [u8; NONCE_LEN];

    fn encrypt(data: &mut Vec<u8>, key: &impl Key, aad: impl AsRef<[u8]>) -> Result<Self::Nonce, Error> {
        encrypt_with_ring(data, key, &ring::aead::CHACHA20_POLY1305, aad)
    }

    fn decrypt<'a>(data: &'a mut [u8], key: &impl Key, nonce: &Self::Nonce, aad: impl AsRef<[u8]>) -> Result<&'a [u8], Error> {
        decrypt_with_ring(data, key, &ring::aead::CHACHA20_POLY1305, nonce.to_owned(), aad)
    }
}

#[inline(always)]
fn encrypt_with_ring(data: &mut Vec<u8>, key: &impl Key, algorithm: &'static Algorithm, aad: impl AsRef<[u8]>) -> Result<[u8;NONCE_LEN], Error> {
    let nonce_sequence = NonceSequence::new()
        .map_err(|_| Error::FailedToCreateNonce)?;

    let nonce_bytes = nonce_sequence.get_current_as_bytes();
    
    let unbound_key = UnboundKey::new( algorithm, key.as_bytes())
        .map_err(|_| Error::WrongKeyLength { expected: algorithm.key_len(), actual: key.as_bytes().len() })?;

    let mut sealing_key = ring::aead::SealingKey::new(unbound_key, nonce_sequence);

    sealing_key
        .seal_in_place_append_tag(Aad::from(aad), data)
        .map_err(|_| Error::FailedToEncryptData)?;

    Ok(nonce_bytes)
}

#[inline(always)]
fn decrypt_with_ring<'a>(data: &'a mut [u8], key: &impl Key, algorithm: &'static Algorithm, nonce: [u8;NONCE_LEN], aad: impl AsRef<[u8]> ) -> Result<&'a [u8], Error> {
    let nonce_sequence = NonceSequence::with_nonce(&Nonce::assume_unique_for_key(nonce));

    let unbound_key = UnboundKey::new(algorithm, key.as_bytes())
        .map_err(|_| Error::WrongKeyLength { expected: algorithm.key_len(), actual: key.as_bytes().len() })?;

    let mut opening_key = OpeningKey::new(unbound_key, nonce_sequence);
    
    let decrypted = opening_key
        .open_in_place(Aad::from(aad), data)
        .map_err(|_| Error::FailedToDecryptData)?;

    Ok(decrypted)
}