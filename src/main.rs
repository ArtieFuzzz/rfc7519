mod encode_decode;
mod structs;
mod signature;

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

    let token = encode_decode::encode_token(claims, "owowhat'sthis")?;

    println!("{token}");

    Ok(())
}
