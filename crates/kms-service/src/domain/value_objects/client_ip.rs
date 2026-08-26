pub struct ClientIp(String);

impl ClientIp {
    //#region new
    pub fn new(ip: String) -> Self {
        Self(ip)
    }

    //#region as_str
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
