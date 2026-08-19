use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Options,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "type", content = "value")]
pub enum AllowedOrigins {
    Any,
    Single(String),
    List(Vec<String>),
}

impl AllowedOrigins {
    pub fn is_allowed(&self, origin: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Single(s) => s == origin,
            Self::List(l) => l.iter().any(|o| o == origin),
        }
    }

    pub fn to_vec(&self) -> Vec<String> {
        match self {
            Self::Any => vec!["*".to_string()],
            Self::Single(s) => vec![s.clone()],
            Self::List(l) => l.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct CorsConfig {
    pub allowed_origin: AllowedOrigins,
    pub allowed_methods: Vec<HttpMethod>,
    pub max_age: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_method_deserialize() {
        let json = r#""GET""#;
        let method: HttpMethod = serde_json::from_str(json).unwrap();
        assert_eq!(method, HttpMethod::Get);
    }

    #[test]
    fn test_cors_config_single_origin() {
        let json = r#"
        {
            "allowed_origin": {
                "type": "Single",
                "value": "http://localhost:3000"
            },
            "allowed_methods": ["GET", "POST"],
            "max_age": 3600
        }
        "#;

        let config: CorsConfig = serde_json::from_str(json).unwrap();

        assert_eq!(
            config.allowed_origin,
            AllowedOrigins::Single("http://localhost:3000".to_string())
        );

        assert!(config.allowed_origin.is_allowed("http://localhost:3000"));
    }

    #[test]
    fn test_cors_config_list_origin() {
        let json = r#"
        {
            "allowed_origin": {
                "type": "List",
                "value": ["http://localhost:3000", "https://app.com"]
            },
            "allowed_methods": ["GET"],
            "max_age": 60
        }
        "#;

        let config: CorsConfig = serde_json::from_str(json).unwrap();

        assert!(config.allowed_origin.is_allowed("https://app.com"));
        assert!(!config.allowed_origin.is_allowed("https://evil.com"));
    }

    #[test]
    fn test_cors_config_any_origin() {
        let json = r#"
        {
            "allowed_origin": {
                "type": "Any"
            },
            "allowed_methods": ["OPTIONS"],
            "max_age": 0
        }
        "#;

        let config: CorsConfig = serde_json::from_str(json).unwrap();

        assert_eq!(config.allowed_origin, AllowedOrigins::Any);
        assert!(config.allowed_origin.is_allowed("cokolwiek"));
    }
}
