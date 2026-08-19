pub struct ClientIp(String);

impl ClientIp {
    pub fn new(ip: String) -> Self {
        Self(ip)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
