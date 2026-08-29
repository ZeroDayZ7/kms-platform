// src/handlers/mod.rs
pub mod admin;
pub mod audit;
pub mod credentials;
pub mod crypto;
pub mod health;
pub mod keys;

pub use admin::*;
pub use audit::*;
pub use credentials::*;
pub use health::*;
pub use keys::*;
