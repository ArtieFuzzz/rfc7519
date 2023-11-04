use hmac::{Hmac, Mac};
use rfc7519::payload::Claims;
use rfc7519::token::{generate, validate};
use sha2::Sha512;

type HS512 = Hmac<Sha512>;
#[test]
fn check_token() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let claims = Claims {
        iss: Some("ArtieFuzzz".to_owned()),
        sub: Some("Token".to_owned()),
        aud: Some("Everyone".to_owned()),
        exp: None,
        nbf: None,
        iat: None,
        jti: None,
    };

    let mac = HS512::new_from_slice(b"super-secret-secret")?;
    let token = generate(mac.clone(), claims)?;
    let is_token_valid = validate(mac, token)?;

    assert!(is_token_valid);

    Ok(())
}
