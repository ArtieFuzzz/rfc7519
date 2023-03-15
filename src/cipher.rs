use hmac::Hmac;
use sha2::Sha512;

pub use hmac::Mac;

macro_rules! impl_cipher {
    ($name:ident, $type:ty) => {
        pub type $name = $type;
    };
}

impl_cipher!(HmacSha512, Hmac<Sha512>);
