use std::error::Error;

use super::signature::{generate as generate_sig, validate as validate_sig};
use super::structs::{Claims, JWTHeader};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::to_string;

pub fn generate(
    claims: Claims,
    secret: String,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let claims_string = URL_SAFE_NO_PAD.encode(to_string(&claims)?);

    let headers = JWTHeader {
        typ: "JWT".into(),
        alg: "HS512".into(),
    };

    let headers_string = URL_SAFE_NO_PAD.encode(to_string(&headers)?);
    let signature = generate_sig(headers_string.clone(), claims_string.clone(), secret);

    let token_parts = vec![headers_string, claims_string, signature];

    Ok(token_parts.join("."))
}

/// Validate a token.
///
/// Returns a boolean indicating whether the token is valid.
pub fn validate(token: String, secret: String) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let token: Vec<String> = token.split('.').map(|s| s.to_string()).collect();

    if token.len() <= 1 {
        return Ok(false);
    }

    if token.len() > 3 {
        return Ok(false);
    }

    validate_sig(token[0].clone(), token[1].clone(), token[2].clone(), secret)
}
