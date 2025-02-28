use super::error::Error;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::{array::TryFromSliceError, fmt::Debug};
use zeroize::ZeroizeOnDrop;


#[cfg_attr(debug_assertions, derive(PartialEq, Eq))]
#[derive(Clone, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct Salt([u8; Self::LENGTH]);

impl Salt {

    pub const LENGTH: usize = 32;

    pub fn new() -> Result<Self, Error> {
        let mut salt = [0u8; Self::LENGTH];
        // make into a static
        SystemRandom::new()
            .fill(&mut salt)
            .map_err(|_| Error::FailedToCreateSalt)?;

        Ok(Self(salt))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_inner(self) -> [u8; Self::LENGTH] {
        self.0
    }
}

impl Default for Salt {
    fn default() -> Self {
        Self([0u8; Self::LENGTH])
    }
}

impl From<[u8; Salt::LENGTH]> for Salt {
    fn from(value: [u8; Salt::LENGTH]) -> Self {
        Self(value)
    }
}

impl TryFrom<Vec<u8>> for Salt {
    type Error = TryFromSliceError;
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(value.as_slice().try_into()?))
    }
}

impl Debug for Salt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Salt(*)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salt_creation() {
        let salt = Salt::new().expect("Failed to create salt");
        assert_eq!(salt.as_bytes().len(), Salt::LENGTH);
    }

    #[test]
    fn test_salt_uniqueness() {
        let salt1 = Salt::new().expect("Failed to create first salt");
        let salt2 = Salt::new().expect("Failed to create second salt");
        assert_ne!(salt1.as_bytes(), salt2.as_bytes());
    }

    #[test]
    fn test_salt_from_array() {
        let bytes = [42u8; Salt::LENGTH];
        let salt = Salt::from(bytes);
        assert_eq!(salt.as_bytes(), &bytes);
    }

    #[test]
    fn test_salt_try_from_vec() {
        // Test successful conversion
        let vec = vec![42u8; Salt::LENGTH];
        let salt = Salt::try_from(vec.clone()).expect("Failed to convert valid vec to salt");
        assert_eq!(salt.as_bytes(), vec.as_slice());

        // Test failed conversion
        let invalid_vec = vec![42u8; Salt::LENGTH - 1];
        assert!(Salt::try_from(invalid_vec).is_err());
    }

    #[test]
    fn test_salt_default() {
        let salt = Salt::default();
        assert_eq!(salt.as_bytes(), &[0u8; Salt::LENGTH]);
    }

    #[test]
    fn test_salt_debug() {
        let salt = Salt::default();
        assert_eq!(format!("{:?}", salt), "Salt(*)");
    }

    #[test]
    fn test_salt_to_inner() {
        let bytes = [42u8; Salt::LENGTH];
        let salt = Salt::from(bytes);
        assert_eq!(salt.to_inner(), bytes);
    }
}
