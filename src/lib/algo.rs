use sha2::{Sha256, Sha384, Sha512};

use hmac::Hmac;

pub trait AlgoToString {
    fn algorithm(self) -> String;
}

macro_rules! impl_cipher {
    ($name:tt, $type:ty) => {
        impl AlgoToString for Hmac<$type> {
            fn algorithm(self) -> String {
                $name.to_string()
            }
        }
    };
}

impl_cipher!("HS512", Sha512);
impl_cipher!("HS256", Sha256);
impl_cipher!("HS386", Sha384);
