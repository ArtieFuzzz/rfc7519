use std::error::Error;

use super::algo::AlgoToString;

use super::signature::{generate as generate_sig, validate as validate_sig};
use super::payload::{Claims, JWTHeader};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::Mac;
use serde_json::to_string;

pub fn generate<M>(mac: M, claims: Claims) -> Result<String, Box<dyn Error + Send + Sync>>
where
    M: Mac + AlgoToString + Clone,
{
    let claims_string = URL_SAFE_NO_PAD.encode(to_string(&claims)?);

    let headers = JWTHeader {
        typ: "JWT".into(),
        alg: mac.clone().algorithm(),
    };

    let headers_string = URL_SAFE_NO_PAD.encode(to_string(&headers)?);
    let signature = generate_sig(mac, headers_string.clone(), claims_string.clone());

    let token_parts = vec![headers_string, claims_string, signature];

    Ok(token_parts.join("."))
}

/// Validate a token.
///
/// Returns a boolean indicating whether the token is valid.
pub fn validate<M: Mac>(mac: M, token: String) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let token: Vec<String> = token.split('.').map(|s| s.to_string()).collect();

    if token.len() <= 1 {
        return Ok(false);
    }

    if token.len() > 3 {
        return Ok(false);
    }

    validate_sig(mac, token[0].clone(), token[1].clone(), token[2].clone())
}
