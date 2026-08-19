use getrandom::getrandom;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_SIZE: usize = 32;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_SIZE]);

impl SecretKey {
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_SIZE];
        // getrandom returns std::io style error; unwrap here is acceptable for key generation
        getrandom(&mut key).expect("OS RNG failed");
        Self(key)
    }

    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

pub fn generate_master_key() -> SecretKey {
    SecretKey::generate()
}
