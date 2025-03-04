use std::fmt::Debug;

use serde::{de::DeserializeOwned, Serialize};

use crate::{traits::key::Key, Error};

pub trait EncryptionAlgorithm {
    type KeyType: Key;
    type Nonce: Debug + Serialize + DeserializeOwned + Clone + Default;

    fn encrypt(data: &mut Vec<u8>, key: &impl Key) -> Result<Self::Nonce, Error>;

    fn decrypt<'a>(data: &'a mut [u8], key: &impl Key, nonce: &Self::Nonce) -> Result<&'a [u8], Error>;
}

