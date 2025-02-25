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
    fn key_data_mut(&mut self) -> &mut [u8] {
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
    fn key_data_mut(&mut self) -> &mut [u8] {
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
