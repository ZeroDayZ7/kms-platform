use std::time::Instant;
use zeroize::Zeroize;

pub struct VhsmState {
    pub initialized: bool,
    pub active_key_version: u32,
    pub master_key: Option<Vec<u8>>,
    pub last_activity: Instant,
}

impl VhsmState {
    pub fn new() -> Self {
        Self {
            initialized: false,
            active_key_version: 0,
            master_key: None,
            last_activity: Instant::now(),
        }
    }

    /// Odświeża znacznik czasu aktywności
    #[allow(dead_code)]
    pub fn touch_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn zeroize_key(&mut self) {
        if let Some(ref mut key) = self.master_key {
            key.zeroize();
        }
        self.master_key = None;
        self.initialized = false;
        self.active_key_version = 0;
    }
}

impl Drop for VhsmState {
    fn drop(&mut self) {
        self.zeroize_key();
    }
}
