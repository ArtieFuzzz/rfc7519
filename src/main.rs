mod signature;
mod structs;
mod token;

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

    let token = token::generate(claims, secret.into())?;

    println!("{token}");

    let valid = token::validate(token, secret.into())?;

    println!("{valid}");

    Ok(())
}
