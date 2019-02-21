// use cfg_if::cfg_if;
use wasm_bindgen::prelude::*;

#[macro_use]
extern crate arrayref;

pub mod aes;
pub mod ecdsa;
pub mod memo;
pub mod private_key;
pub mod public_key;
pub mod signature;

#[wasm_bindgen]
pub struct Ecc {
    private_key: private_key::PrivateKey,
}

#[wasm_bindgen]
impl Ecc {
    pub fn from_seed(seed: &str) -> Ecc {
        let private_key = private_key::PrivateKey::from_seed(&seed).unwrap();
        Ecc { private_key }
    }

    pub fn from_buffer(buf: &[u8]) -> Ecc {
        let private_key = private_key::PrivateKey::from_buffer(&buf).unwrap();
        Ecc { private_key }
    }

    pub fn to_wif(&self) -> String {
        self.private_key.to_wif()
    }

    pub fn to_public_str(&self, prefix: &str) -> String {
        self.private_key.public_key.to_string(Some(prefix))
    }

    pub fn sign_hex(&self, hex: &str) -> String {
        signature::Signature::sign_hex(hex, &self.private_key.secret_key).to_hex()
    }

    pub fn sign_buffer(&self, buffer: &[u8]) -> Vec<u8> {
        signature::Signature::sign_buffer(buffer, &self.private_key.secret_key).to_buffer()
    }
    pub fn sign_buffer_to_hex(&self, buffer: &[u8]) -> String {
        signature::Signature::sign_buffer(buffer, &self.private_key.secret_key).to_hex()
    }

    pub fn decode_memo(&self, public_key: &str, nonce: u64, cipher: &str) -> String {
        crate::memo::Memo::decrypt_message(&self.private_key, &public_key, nonce, cipher)
    }
}

// #[wasm_bindgen]

#[cfg(test)]
mod tests {
    // use crate::aes::Aes;
    use crate::private_key::PrivateKey;
    use crate::public_key::PublicKey;
    use crate::signature::Signature;
    use bigint::U256 as BigInt;
    use sha2::{Digest, Sha256};

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
        let public_key_str = key.to_string(None);
        let expected = "7HJSZFyj6Rt6xS3ZLvp6pWMnzzJMyj9pAnDeEmciwmyX2kHhqv";
        assert_eq!(expected, public_key_str);
        let create_test_seed = "create-test20ownerqwer1234qwer1234";
    }

    #[test]
    fn public_string_with_prefix() {
        let seed = "create-test20ownerqwer1234qwer1234";
        let key = PrivateKey::from_seed(seed).unwrap().public_key;
        let public_key_str = key.to_string(Some("CYB"));
        let expected = "CYB5577JwE4MLsYooqAdWBwV7pam7YmvqUgyGWHvCwPRjw5Y58Rsa";
        assert_eq!(expected, public_key_str);
    }

    #[test]
    fn public_from_buffer() {
        let buffer = [
            3, 59, 48, 118, 96, 136, 182, 162, 78, 173, 168, 43, 207, 202, 177, 194, 16, 34, 121,
            40, 207, 73, 222, 156, 210, 73, 83, 193, 230, 252, 90, 31, 78,
        ];
        let key = PublicKey::from_buffer(&buffer);
        let public_key_str = key.to_string(None);
        let expected = "7HJSZFyj6Rt6xS3ZLvp6pWMnzzJMyj9pAnDeEmciwmyX2kHhqv";
        assert_eq!(expected, public_key_str);
        // assert_eq!("5KhczK24xDTxQvc5mmK8xnKj4yHtxz6ChWN8rQ1nQHcooJkAbbo", key.to_wif());
    }
    #[test]
    fn public_from_str() {
        let buffer = [
            3, 59, 48, 118, 96, 136, 182, 162, 78, 173, 168, 43, 207, 202, 177, 194, 16, 34, 121,
            40, 207, 73, 222, 156, 210, 73, 83, 193, 230, 252, 90, 31, 78,
        ];
        let expected = "CYB7HJSZFyj6Rt6xS3ZLvp6pWMnzzJMyj9pAnDeEmciwmyX2kHhqv";
        let key = PublicKey::from_string(&expected, Some("CYB"));
        let public_key_str = key.to_string(Some("CYB"));
        assert_eq!(public_key_str, expected);
        assert_eq!(buffer[..], key.to_buffer()[..]);
    }

    #[test]
    fn sign_buffer() {
        let first =
            "hereisthefirststringhereisthefirststringhereisthefirststringhereisthefirststring";
        let second =
            "hereisthesecondstringhereisthesecondstringhereisthesecondstringhereisthesecondstring";
        let third =
            "hereisthethirdstringhereisthethirdstringhereisthethirdstringhereisthethirdstring";
        let seed = "hereisthesimpleseed";

        let sk = PrivateKey::from_seed(&seed).unwrap().secret_key;
        let signature1 = Signature::sign_buffer(first.as_bytes(), &sk).to_hex();
        let signature2 = Signature::sign_buffer(second.as_bytes(), &sk).to_hex();
        let signature3 = Signature::sign_buffer(third.as_bytes(), &sk).to_hex();

        assert_eq!(signature1, "2064a9039a0e8c5af90b8d1918451f4303a628ce2887e997a16d61efed928e88a11267f9fc1ecf91fc09c73ed9ca7f542887f08cb54c2efce56e243bebb0833a17");
        assert_eq!(signature2, "20752063fafc29b593802687dd6b6b718a932212e7465d044b99a502dcc9fa083a1fd195d943d5002ea8cdc32a3e20e160b8c5af1ec7a6f6a1101193aa68405842");
        assert_eq!(signature3, "1f4dfdb566e1b18a3773800cf0c30b44ec56565ead99d7034385e7792d8ed24bc652b256cdb573ed3c3074a79a876e4f5a1cafff3fdd53061b02e0fba70634decc");
    }

    #[test]
    fn bignum_test() {
        let origin_num: &str = "255";
        let bg = BigInt::from_dec_str(origin_num).unwrap();
        // bg.add(2);
        assert_eq!(bg.to_string(), "255");
    }

    #[test]
    // fn aes() {
    //     let seed = "hereisthefirststring";
    //     let aes = Aes::from_seed(Some(&seed));
    //     assert_eq!("", "2");
    // }
    #[test]
    fn decode_memo() {
        let msg1 = "hereisa test message!@#$%";
        let msg2 = "hereis the second2 test message!@#$%";
        let msg3 = "hereis the third test message!@#$%";
        let msg4 = "hereis the forth test message!@#$%";

        let nonce = 395460150602219;
        let seed = "ldw-formatownerqwer1234qwer1234";
        let pubkey = "7bAJvGEX9xbEEuE4ho8zaac1vppbGYVxhaP4Lebu3DKuo2FTmb";

        let memo1 = crate::memo::Memo::decrypt_message(
            &PrivateKey::from_seed(&seed).unwrap(),
            &pubkey,
            nonce,
            &String::from("8421e6582e1fa5bf0b42b8aaa54a6ee231aa5015f5dbf9ebf79e52582ce17d9f"),
        );
        let memo2 = crate::memo::Memo::decrypt_message(
            &PrivateKey::from_seed(&seed).unwrap(),
            &pubkey,
            nonce,
            &String::from("37f0592465cc5f241f6e720468eb4eef9301475b33aac3c3fe3d103656704006adaeeef1b65cd8bd37b22d507a100852"),
        );
        let memo3 = crate::memo::Memo::decrypt_message(
            &PrivateKey::from_seed(&seed).unwrap(),
            &pubkey,
            nonce,
            &String::from("67a2a29a0ea612a25d7f3bf9895ca5755fc417f0398249f8ae98c274ff1e8ddf649c26fe95bbcf83f844fdc68adcc976"),
        );
        let memo4 = crate::memo::Memo::decrypt_message(
            &PrivateKey::from_seed(&seed).unwrap(),
            &pubkey,
            nonce,
            &String::from("92a0d5cb6d70708f94b55766a77ac7c9cce6c0d63513bd8bcc3a0968c90dbe20c177d3a72f6dd9e4b52549b3f20491a9"),
        );

        assert_eq!(memo1, msg1);
        assert_eq!(memo2, msg2);
        assert_eq!(memo3, msg3);
        assert_eq!(memo4, msg4);
    }
    #[test]
    fn encode_memo() {
        let msg = "hereisa test message!@#$%";
        let msg2 = "hereis the second2 test message!@#$%";
        let msg3 = "hereis the third test message!@#$%";
        let msg4 = "hereis the forth test message!@#$%";
        let nonce = 395460150602219u64;
        let seed = "ldw-formatownerqwer1234qwer1234";
        let pubkey = "7bAJvGEX9xbEEuE4ho8zaac1vppbGYVxhaP4Lebu3DKuo2FTmb";

        let cipher1 = crate::memo::Memo::encrypt_message(
            &PrivateKey::from_seed(&seed).unwrap(),
            &PublicKey::from_string(&pubkey, None),
            &String::from(msg),
            nonce,
        );
        let cipher2 = crate::memo::Memo::encrypt_message(
            &PrivateKey::from_seed(&seed).unwrap(),
            &PublicKey::from_string(&pubkey, None),
            &String::from(msg2),
            nonce,
        );
        let cipher3 = crate::memo::Memo::encrypt_message(
            &PrivateKey::from_seed(&seed).unwrap(),
            &PublicKey::from_string(&pubkey, None),
            &String::from(msg3),
            nonce,
        );
        let cipher4 = crate::memo::Memo::encrypt_message(
            &PrivateKey::from_seed(&seed).unwrap(),
            &PublicKey::from_string(&pubkey, None),
            &String::from(msg4),
            nonce,
        );

        assert_eq!(
            *hex_d_hex::lower_hex(&cipher1),
            "8421e6582e1fa5bf0b42b8aaa54a6ee231aa5015f5dbf9ebf79e52582ce17d9f"
        );
        assert_eq!(*hex_d_hex::lower_hex(&cipher2), "37f0592465cc5f241f6e720468eb4eef9301475b33aac3c3fe3d103656704006adaeeef1b65cd8bd37b22d507a100852");
        assert_eq!(*hex_d_hex::lower_hex(&cipher3), "67a2a29a0ea612a25d7f3bf9895ca5755fc417f0398249f8ae98c274ff1e8ddf649c26fe95bbcf83f844fdc68adcc976");
        assert_eq!(*hex_d_hex::lower_hex(&cipher4), "92a0d5cb6d70708f94b55766a77ac7c9cce6c0d63513bd8bcc3a0968c90dbe20c177d3a72f6dd9e4b52549b3f20491a9");
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
