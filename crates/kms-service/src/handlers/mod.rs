// src/handlers/mod.rs
pub mod admin;
pub mod agent;
pub mod audit;
pub mod crypto;
pub mod health;
pub mod keys;

pub use admin::*;
pub use agent::*;
pub use audit::*;
pub use health::*;
pub use keys::*;
