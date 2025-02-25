use std::num::NonZeroU32;

use ring::pbkdf2::{self, PBKDF2_HMAC_SHA256};
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
            key.key_data_mut(),
        );
        key
    }

    fn key_data_mut(&mut self) -> &mut [u8];

    fn as_bytes(&self) -> &[u8];

    fn key_len(&self) -> usize;
}
 

