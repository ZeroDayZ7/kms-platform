pub mod ceremony;
pub mod crypto;
pub mod hsm;

#[cfg(test)]
mod tests {
    #[test]
    fn sanity() {
        // basic compile-time check for modules
        let _ = crate::crypto::keys::KEY_SIZE;
    }
}
