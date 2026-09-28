use std::time::Instant;
use zeroize::{Zeroize, Zeroizing};

pub struct VhsmState {
    pub initialized: bool,
    pub active_key_version: u32,
    pub master_key: Option<Zeroizing<Vec<u8>>>,
    pub unseal_started_at: Option<Instant>,
    /// Map of loaded CA private keys held encrypted in RAM (Zeroizing) keyed by ca_tag
    pub active_ca_keys: std::collections::HashMap<String, Zeroizing<Vec<u8>>>,
}

impl VhsmState {
    //#region new
    pub fn new() -> Self {
        Self {
            initialized: false,
            active_key_version: 0,
            master_key: None,
            unseal_started_at: None,
            active_ca_keys: std::collections::HashMap::new(),
        }
    }

    /// Rozpoczyna stoper 15 minut dla procedury Unseal (jeśli jeszcze nie ruszył)
    #[allow(dead_code)]
    //#region start_unseal_timer
    pub fn start_unseal_timer(&mut self) {
        if self.unseal_started_at.is_none() {
            self.unseal_started_at = Some(Instant::now());
        }
    }

    /// Anuluje stoper Unsealu po pomyślnym odblokowaniu vHSM
    #[allow(dead_code)]
    //#region cancel_unseal_timer
    pub fn cancel_unseal_timer(&mut self) {
        self.unseal_started_at = None;
    }

    /// Bezpieczne czyszczenie klucza w pamięci RAM
    //#region zeroize_key
    pub fn zeroize_key(&mut self) {
        if let Some(mut key) = self.master_key.take() {
            key.zeroize();
        }
        self.initialized = false;
        self.active_key_version = 0;
        self.unseal_started_at = None;
        // zeroize loaded CA keys
        for (_k, mut v) in self.active_ca_keys.drain() {
            v.zeroize();
        }
    }
}

impl Default for VhsmState {
    //#region default
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for VhsmState {
    //#region drop
    fn drop(&mut self) {
        self.zeroize_key();
    }
}
