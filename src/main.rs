#[allow(special_module_name)]
mod lib;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use lib::payload::Claims;
use lib::token::{generate, validate};


type HmacSha256 = Hmac<Sha256>;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let claims = Claims {
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
    let token = generate(mac.clone(), claims)?;

    println!("{token}");

    let valid = validate(mac, token)?;

    assert!(valid);

    Ok(())
}
