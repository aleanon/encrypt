use ring::{aead::{Nonce, NonceSequence as RingNonceSequence, NONCE_LEN}, rand::{SecureRandom, SystemRandom}};

use crate::error::CryptoError;


pub struct NonceSequence(Nonce);

impl NonceSequence {
    pub fn new() -> Result<Self, CryptoError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| CryptoError::FailedToCreateNonce)?;

        Ok(Self(Nonce::assume_unique_for_key(nonce_bytes)))
    }

    pub fn with_nonce(nonce: &Nonce) -> Self {
        Self(Nonce::assume_unique_for_key(nonce.as_ref().clone()))
    }

    pub fn get_current_as_bytes(&self) -> [u8; NONCE_LEN] {
        self.0.as_ref().clone()
    }
}


impl RingNonceSequence for NonceSequence {
    fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
        let nonce = Nonce::assume_unique_for_key(self.get_current_as_bytes());
        Ok(nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_creation() {
        let nonce = NonceSequence::new().expect("Failed to create nonce");
        assert_eq!(nonce.get_current_as_bytes().len(), NONCE_LEN);
    }

    #[test]
    fn test_nonce_uniqueness() {
        let nonce1 = NonceSequence::new().expect("Failed to create first nonce");
        let nonce2 = NonceSequence::new().expect("Failed to create second nonce");
        
        assert_ne!(nonce1.get_current_as_bytes(), nonce2.get_current_as_bytes());
    }

    #[test]
    fn test_nonce_with_bytes() {
        let original_nonce = NonceSequence::new().expect("Failed to create nonce");
        let bytes = original_nonce.get_current_as_bytes();
        let recreated_nonce = NonceSequence::with_nonce(&Nonce::assume_unique_for_key(bytes));
        
        assert_eq!(original_nonce.get_current_as_bytes(), recreated_nonce.get_current_as_bytes());
    }

    #[test]
    fn test_nonce_advance() {
        let mut nonce = NonceSequence::new().expect("Failed to create nonce");
        let original_bytes = nonce.get_current_as_bytes();
        
        let advanced_nonce = nonce.advance().expect("Failed to advance nonce");
        assert_eq!(advanced_nonce.as_ref(), &original_bytes);
    }
}
