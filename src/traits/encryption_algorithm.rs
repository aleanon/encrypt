use ring::aead::Algorithm;

use super::key::Key;

pub trait EncryptionAlgorithm {
    const ALGORITHM_TYPE: &'static Algorithm;
    type KeyType: Key;
}

