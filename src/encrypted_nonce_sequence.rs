use ring::{aead::{Nonce, NonceSequence, NONCE_LEN}, rand::{SecureRandom, SystemRandom}};

use crate::error::Error;

pub struct EncryptedNonceSequence(Nonce);

impl EncryptedNonceSequence {
    pub fn new() -> Result<Self, Error> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| Error::FailedToCreateNonce)?;

        Ok(Self(Nonce::assume_unique_for_key(nonce_bytes)))
    }

    pub fn with_nonce(nonce: &Nonce) -> Self {
        Self(Nonce::assume_unique_for_key(nonce.as_ref().clone()))
    }

    pub fn get_current_as_bytes(&self) -> [u8; NONCE_LEN] {
        self.0.as_ref().clone()
    }
}


impl NonceSequence for EncryptedNonceSequence {
    fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
        let nonce = Nonce::assume_unique_for_key(self.get_current_as_bytes());
        Ok(nonce)
    }
}