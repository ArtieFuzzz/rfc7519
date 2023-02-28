use serde::{Deserialize, Serialize};

/// JWT Claims
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer
    pub iss: Option<String>,
    /// Subject
    pub sub: Option<String>,
    /// Audience
    pub aud: Option<String>,
    /// Expiration. EPOCH
    pub exp: Option<i64>,
    /// Not Before
    pub nbf: Option<i64>,
    /// Issued At
    pub iat: Option<i64>,
    /// JWT ID
    pub jti: Option<String>,
}

/// Internal
#[derive(Debug, Serialize, Deserialize)]
pub struct JWTHeader {
    /// The encoding of the token
    /// i.e HS256
    pub alg: String,
    /// The type of the token
    /// i.e JWT
    pub typ: String,
}
