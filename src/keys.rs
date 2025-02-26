use std::fmt::Debug;
use zeroize::ZeroizeOnDrop;
use crate::traits::key::Key;



#[derive(ZeroizeOnDrop)]
pub struct Key128Bit([u8;Self::LENGTH]);

impl Key128Bit {
    const LENGTH: usize = 16;
}

impl Default for Key128Bit {
    fn default() -> Self {
        Self([0u8; Self::LENGTH])
    }
}


impl Key for Key128Bit {
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn key_len(&self) -> usize {
        Self::LENGTH
    }
}

impl Debug for Key128Bit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key128Bit(masked)")
    }
}



#[cfg_attr(test, derive(Clone, PartialEq))]
#[derive(ZeroizeOnDrop)]
pub struct Key256Bit([u8;Self::LENGTH]);

impl Key256Bit {
    const LENGTH: usize = 32;
}

impl Default for Key256Bit {
    fn default() -> Self {
        Self([0u8; Self::LENGTH])
    }
}

impl Key for Key256Bit {
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn key_len(&self) -> usize {
        Self::LENGTH
    }
}

impl Debug for Key256Bit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key256Bit(masked)")
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use crate::salt::Salt;
    use super::*;

    #[test]
    fn test_key_lengths() {
        let key128 = Key128Bit::default();
        let key256 = Key256Bit::default();
        assert_eq!(key128.key_len(), 16);
        assert_eq!(key256.key_len(), 32);
    }

    #[test]
    fn test_default_keys_are_zero() {
        let key128 = Key128Bit::default();
        let key256 = Key256Bit::default();
        assert!(key128.as_bytes().iter().all(|&b| b == 0));
        assert!(key256.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_debug_format() {
        let key128 = Key128Bit::default();
        let key256 = Key256Bit::default();
        assert_eq!(format!("{:?}", key128), "Key128Bit(masked)");
        assert_eq!(format!("{:?}", key256), "Key256Bit(masked)");
    }

    #[test]
    fn test_key_derivation() {
        let salt = Salt::new().expect("Failed to create salt");
        let iterations = NonZeroU32::new(1).unwrap();
        
        let key1 = Key256Bit::create_key(iterations, "secret", &salt);
        let key2 = Key256Bit::create_key(iterations, "secret", &salt);
        assert_eq!(key1.as_bytes(), key2.as_bytes());
        
        let key3 = Key256Bit::create_key(iterations, "different", &salt);
        assert_ne!(key1.as_bytes(), key3.as_bytes());
        
        let salt2 = Salt::new().expect("Failed to create second salt");
        let key4 = Key256Bit::create_key(iterations, "secret", &salt2);
        assert_ne!(key1.as_bytes(), key4.as_bytes());
    }

    #[test]
    fn test_key_bytes_mutation() {
        let mut key = Key256Bit::default();
        let bytes = key.as_bytes_mut();
        bytes[0] = 42;
        assert_eq!(key.as_bytes()[0], 42);
    }

    #[test]
    fn test_different_iteration_counts() {
        let salt = Salt::new().expect("Failed to create salt");
        let secret = "test_secret";
        
        let key1 = Key256Bit::create_key(NonZeroU32::new(1).unwrap(), secret, &salt);
        let key2 = Key256Bit::create_key(NonZeroU32::new(2).unwrap(), secret, &salt);
        
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }
}
