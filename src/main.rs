use hmac::{Hmac, Mac};
use sha2::Sha256;

mod cipher;
mod signature;
mod structs;
mod token;

type HmacSha256 = Hmac<Sha256>;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let claims = structs::Claims {
        iss: Some("Artie themselves".into()),
        sub: Some("Do whatever".into()),
        aud: Some("Arteh".into()),
        exp: None,
        nbf: None,
        iat: None,
        jti: None,
    };

    let secret = "owowhat'sthis";
    let mac = HmacSha256::new_from_slice(secret.as_bytes())?;
    let token = token::generate(mac.clone(), claims)?;

    println!("{token}");

    let valid = token::validate(mac, token)?;

    assert!(valid);

    Ok(())
}
