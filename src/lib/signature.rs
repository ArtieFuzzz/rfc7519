use std::error::Error;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::Mac;

pub fn generate<M: Mac>(mut mac: M, header: String, claims: String) -> String {
    let claim_header = vec![header, claims];

    mac.update(claim_header.join(".").as_bytes());

    let result = mac.finalize();

    URL_SAFE_NO_PAD.encode(result.into_bytes())
}

pub fn validate<M: Mac>(
    mut mac: M,
    header: String,
    claims: String,
    signature: String,
) -> Result<bool, Box<dyn Error + Send + Sync>> {
    let claim_header = vec![header, claims];

    mac.update(claim_header.join(".").as_bytes());

    let sig = URL_SAFE_NO_PAD.decode(signature)?;

    match mac.verify_slice(&sig) {
        Ok(_) => Ok(true),
        Err(why) => Err(why.into()),
    }
}
