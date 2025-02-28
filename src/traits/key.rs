use std::num::NonZeroU32;

use ring::{pbkdf2::{self, PBKDF2_HMAC_SHA256}, rand::{SecureRandom, SystemRandom}};
use zeroize::ZeroizeOnDrop;

use crate::salt::Salt;


pub trait Key: Default + ZeroizeOnDrop {

    fn create_key(iterations: NonZeroU32, secret: impl AsRef<[u8]>, salt: &Salt) -> Self {
        let mut key = Self::default();

        pbkdf2::derive(
            PBKDF2_HMAC_SHA256,
            iterations,
            salt.as_bytes(),
            secret.as_ref(),
            key.as_bytes_mut(),
        );
        key
    }

    fn create_random_key() -> Result<Self, crate::Error> {
        let mut key = Self::default();
        SystemRandom::new()
            .fill(key.as_bytes_mut())
            .map_err(|_| crate::Error::FailedToCreateRandomKey)?;
        Ok(key)
    }

    fn as_bytes_mut(&mut self) -> &mut [u8];

    fn as_bytes(&self) -> &[u8];

    fn key_len(&self) -> usize;
}
 

