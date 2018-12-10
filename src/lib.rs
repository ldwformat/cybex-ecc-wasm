extern crate bigint;
extern crate cfg_if;
extern crate hex_d_hex;
extern crate sha2;
extern crate wasm_bindgen;

use cfg_if::cfg_if;
use wasm_bindgen::prelude::*;

#[macro_use]
extern crate arrayref;

pub mod private_key;
pub mod public_key;
pub mod signature;
pub mod ecdsa;

#[wasm_bindgen]
pub struct Ecc {
    private_key: private_key::PrivateKey,
}
#[wasm_bindgen]
impl Ecc {
    pub fn new(seed: &str) -> Ecc {
        let private_key = private_key::PrivateKey::from_seed(&seed).unwrap();
        Ecc { private_key }
    }

    pub fn sign_hex(&self, hex: &str) -> String {
        signature::Signature::sign_hex(hex, &self.private_key.secret_key).to_hex()
    }
}

// #[wasm_bindgen]

#[cfg(test)]
mod tests {
    use super::bigint::U256 as BigInt;
    use super::private_key::PrivateKey;
    use super::public_key::PublicKey;
    use super::sha2::{Digest, Sha256};
    use super::signature::Signature;

    #[test]
    fn sha256() {
        let str = "hello world";
        let mut hasher = Sha256::new();
        hasher.input(str.as_bytes());
        assert_eq!(
            hasher.result().as_slice(),
            &*hex_d_hex::dhex("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
                .as_slice()
        );
    }

    #[test]
    fn private_wif() {
        let seed = "hereisasimpletestseed";
        let key = PrivateKey::from_seed(seed).unwrap();
        println!("Got key: {:?}", key);
        assert_eq!(
            "5JuuZhBAinVM4i3MmQc9hx7ML9UCwjzSTqJEpcpUa1TnRBmaNqA",
            key.to_wif()
        );
        // assert_eq!("5KhczK24xDTxQvc5mmK8xnKj4yHtxz6ChWN8rQ1nQHcooJkAbbo", key.to_wif());
    }

    #[test]
    fn public_buffer() {
        let seed = "hereisasimpletestseed";
        let key = PrivateKey::from_seed(seed).unwrap().public_key;
        let public_key_str = key.to_buffer();
        let expected: [u8; 33] = [
            3, 59, 48, 118, 96, 136, 182, 162, 78, 173, 168, 43, 207, 202, 177, 194, 16, 34, 121,
            40, 207, 73, 222, 156, 210, 73, 83, 193, 230, 252, 90, 31, 78,
        ];
        assert_eq!(expected[..], public_key_str[..]);
    }

    #[test]
    fn public_string() {
        let seed = "hereisasimpletestseed";
        let key = PrivateKey::from_seed(seed).unwrap().public_key;
        let public_key_str = key.to_string();
        let expected = "7HJSZFyj6Rt6xS3ZLvp6pWMnzzJMyj9pAnDeEmciwmyX2kHhqv";
        assert_eq!(expected, public_key_str);
        // assert_eq!("5KhczK24xDTxQvc5mmK8xnKj4yHtxz6ChWN8rQ1nQHcooJkAbbo", key.to_wif());
    }
    #[test]
    fn public_from_buffer() {
        let buffer = [
            3, 59, 48, 118, 96, 136, 182, 162, 78, 173, 168, 43, 207, 202, 177, 194, 16, 34, 121,
            40, 207, 73, 222, 156, 210, 73, 83, 193, 230, 252, 90, 31, 78,
        ];
        let key = PublicKey::from_buffer(&buffer);
        let public_key_str = key.to_string();
        let expected = "7HJSZFyj6Rt6xS3ZLvp6pWMnzzJMyj9pAnDeEmciwmyX2kHhqv";
        assert_eq!(expected, public_key_str);
        // assert_eq!("5KhczK24xDTxQvc5mmK8xnKj4yHtxz6ChWN8rQ1nQHcooJkAbbo", key.to_wif());
    }

    #[test]
    fn sign_buffer() {
        let first = "hereisthefirststringhereisthefirststringhereisthefirststringhereisthefirststring";
        let second = "hereisthesecondstringhereisthesecondstringhereisthesecondstringhereisthesecondstring";
        let third = "hereisthethirdstringhereisthethirdstringhereisthethirdstringhereisthethirdstring";
        let seed = "hereisthesimpleseed";
        // println!("{:x?}", first.as_bytes());
        // println!("{:x?}", second.as_bytes());
        println!("{:x?}", third.as_bytes());
        let sk = PrivateKey::from_seed(&seed).unwrap().secret_key;

        let signature1 = Signature::sign_buffer(first.as_bytes(), &sk).to_hex();
        let signature2 = Signature::sign_buffer(second.as_bytes(), &sk).to_hex();
        let signature3 = Signature::sign_buffer(third.as_bytes(), &sk).to_hex();

        // assert_eq!(signature1, "2064a9039a0e8c5af90b8d1918451f4303a628ce2887e997a16d61efed928e88a11267f9fc1ecf91fc09c73ed9ca7f542887f08cb54c2efce56e243bebb0833a17");
        // assert_eq!(signature2, "20752063fafc29b593802687dd6b6b718a932212e7465d044b99a502dcc9fa083a1fd195d943d5002ea8cdc32a3e20e160b8c5af1ec7a6f6a1101193aa68405842");
        assert_eq!(signature3, "1f2a7505b0a536a43b04213dc5de560aa52423616f3af7735a6e12352e5acd522609ee667c2f3de9cddf1deaf884be6df40ff815cfca106cc67b7b916649c01400");
    }

    #[test]
    fn bignum_test() {
        let origin_num: &str = "255";
        let bg = BigInt::from_dec_str(origin_num).unwrap();
        // bg.add(2);
        assert_eq!(bg.to_string(), "255");
    }

    #[test]
    fn sign_from_buffer() {
        let buf = [
            31, 120, 26, 9, 27, 107, 196, 100, 73, 223, 36, 220, 81, 32, 197, 195, 194, 96, 139,
            248, 160, 133, 113, 182, 149, 30, 242, 40, 50, 57, 249, 139, 168, 49, 13, 5, 209, 252,
            26, 213, 75, 14, 95, 109, 150, 171, 161, 213, 201, 39, 51, 55, 124, 41, 137, 27, 167,
            145, 215, 201, 113, 59, 177, 89, 188,
        ];
        let sig = Signature::from_buffer(&buf);
        let res: Vec<u8> = buf.iter().map(|&x| x).collect();
        assert_eq!(sig.to_buffer(), res);
    }
}
