use ring::aead::Algorithm;

use crate::{keys::{Key128Bit, Key256Bit}, traits::encryption_algorithm::EncryptionAlgorithm};

pub struct AES128GCM;

impl EncryptionAlgorithm for AES128GCM {
    const ALGORITHM_TYPE: &'static Algorithm = &ring::aead::AES_128_GCM;
    type KeyType = Key128Bit;
}

pub struct AES256GCM;

impl EncryptionAlgorithm for AES256GCM {
    const ALGORITHM_TYPE: &'static Algorithm = &ring::aead::AES_256_GCM;
    type KeyType = Key256Bit;
}
pub struct CHACHA20POLY1305;

impl EncryptionAlgorithm for CHACHA20POLY1305 {
    const ALGORITHM_TYPE: &'static Algorithm = &ring::aead::CHACHA20_POLY1305;
    type KeyType = Key256Bit;
}