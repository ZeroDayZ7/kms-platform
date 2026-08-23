use std::time::Instant;
use zeroize::Zeroize;

pub struct VhsmState {
    pub initialized: bool,
    pub active_key_version: u32,
    pub master_key: Option<Vec<u8>>,
    /// Znacznik czasu rozpoczęcia procedury Unseal (pierwszego wgranego udziału)
    pub unseal_started_at: Option<Instant>,
}

impl VhsmState {
    pub fn new() -> Self {
        Self {
            initialized: false,
            active_key_version: 0,
            master_key: None,
            unseal_started_at: None,
        }
    }

    /// Rozpoczyna stoper 15 minut dla procedury Unseal (jeśli jeszcze nie ruszył)
    #[allow(dead_code)]
    pub fn start_unseal_timer(&mut self) {
        if self.unseal_started_at.is_none() {
            self.unseal_started_at = Some(Instant::now());
        }
    }

    /// Anuluje stoper Unsealu po pomyślnym odblokowaniu vHSM
    #[allow(dead_code)]
    pub fn cancel_unseal_timer(&mut self) {
        self.unseal_started_at = None;
    }

    /// Bezpieczne czyszczenie klucza w pamięci RAM
    pub fn zeroize_key(&mut self) {
        if let Some(ref mut key) = self.master_key {
            key.zeroize();
        }
        self.master_key = None;
        self.initialized = false;
        self.active_key_version = 0;
        self.unseal_started_at = None;
    }
}

impl Default for VhsmState {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for VhsmState {
    fn drop(&mut self) {
        self.zeroize_key();
    }
}
