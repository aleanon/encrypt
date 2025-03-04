mod encrypted;
mod key_salt_pair;
mod error;
mod nonce_sequence;
mod salt;
pub mod algorithms;
pub mod traits;
pub mod keys;

pub use salt::Salt;
pub use key_salt_pair::KeySaltPair;
pub use error::Error;

#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
