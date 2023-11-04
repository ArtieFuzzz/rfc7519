use sha2::{Sha256, Sha384, Sha512};

use hmac::Hmac;

pub trait WithType {
    fn cipher_type(self) -> String;
}

macro_rules! impl_cipher {
    ($name:tt, $type:ty) => {
        impl WithType for Hmac<$type> {
            fn cipher_type(self) -> String {
                $name.to_string()
            }
        }
    };
}

impl_cipher!("HS512", Sha512);
impl_cipher!("HS256", Sha256);
impl_cipher!("HS386", Sha384);
