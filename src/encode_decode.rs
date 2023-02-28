use std::error::Error;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use super::structs::{Claims, JWTHeader};
use super::signature::generate_sig;
use serde_json::to_string;



pub fn encode_token(claims: Claims, secret: impl Into<String>) -> Result<String, Box<dyn Error + Send + Sync>> {
  let claims_string = URL_SAFE_NO_PAD.encode(to_string(&claims)?);
  
  let headers = JWTHeader {
    typ: "JWT".into(),
    alg: "HS256".into(),
  };

  let headers_string = URL_SAFE_NO_PAD.encode(to_string(&headers)?);

  let secret = secret.into();

  let signature = generate_sig(claims_string.clone(), headers_string.clone(), secret);

  let token_parts = vec![headers_string, claims_string, signature];

  Ok(token_parts.join("."))
}