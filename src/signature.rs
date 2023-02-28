use std::error::Error;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub type HmacSha256 = Hmac<Sha256>;

pub fn generate_sig(header: String, claims: String, secret: String) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("Error creating HMAC");

    let claim_header = vec![header, claims];

    mac.update(claim_header.join(".").as_bytes());

    let result = mac.finalize();

    URL_SAFE_NO_PAD.encode(result.into_bytes())
}

pub fn validate_sig(
    header: String,
    claims: String,
    signature: String,
    secret: String,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("Error creating HMAC");
    
    let claim_header = vec![header, claims];

    mac.update(claim_header.join(".").as_bytes());

    let sig = URL_SAFE_NO_PAD.decode(signature)?;

    match mac.verify_slice(&sig) {
        Ok(_) => Ok(true),
        Err(why) => {
            println!("{why:?} {why}");
            Ok(false)
    }
  }
}
