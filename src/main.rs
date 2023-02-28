mod encode_decode;
mod signature;
mod structs;

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

    let token = encode_decode::encode_token(claims, secret.into())?;

    println!("{token}");

    let valid = encode_decode::validate(token, secret.into())?;

    println!("{valid}");

    Ok(())
}
