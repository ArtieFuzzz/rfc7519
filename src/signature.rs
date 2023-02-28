use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub type HmacSha256 = Hmac<Sha256>;

pub fn generate_sig(claims: String, header: String, secret: String) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("Couldn't generate signature");

    let claim_header = vec![header, claims];

    // let mut claim_header = String::from("");

    // claim_header.push_str(&header);
    // claim_header.push_str(&claims);

    mac.update(claim_header.join(".").as_bytes());

    let result = mac.finalize();

    URL_SAFE_NO_PAD.encode(result.into_bytes())
}
