extern crate crypto;
extern crate hex_d_hex;

pub mod private_key;
pub mod public_key;
pub mod signature;

#[cfg(test)]
mod tests {
    use super::crypto::digest::Digest;
    use super::crypto::sha2::Sha256;
    use super::private_key::PrivateKey;
    use super::public_key::PublicKey;
    use super::signature::Signature;

    #[test]
    fn sha256() {
        let mut hasher = Sha256::new();
        hasher.input_str("hello world");
        assert_eq!(
            hasher.result_str(),
            concat!(
                "b94d27b9934d3e08a52e52d7da7dabfa",
                "c484efe37a5380ee9088f7ace2efcde9"
            )
        );
    }

    #[test]
    fn private_wif() {
        let seed = "hereisasimpletestseed";
        let key = PrivateKey::from_seed(seed).unwrap();
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
        let str = "Hereisatestbuffer";
        let seed = "hereisasimpletestseed";
        let sk = PrivateKey::from_seed(&seed).unwrap().secret_key;
        println!("Str to be signed: {:x?}", str.as_bytes());
        let signature = Signature::sign_buffer(str.as_bytes(), sk);
        let result = signature.to_hex();
        println!("Hex: {:?}", result);
        assert_eq!(result, "1f781a091b6bc46449df24dc5120c5c3c2608bf8a08571b6951ef2283239f98ba8310d05d1fc1ad54b0e5f6d96aba1d5c92733377c29891ba791d7c9713bb159bc");
    }

    // #[test]
    // fn sign_from_buffer() {
    //     let buf = [
    //         31, 120, 26, 9, 27, 107, 196, 100, 73, 223, 36, 220, 81, 32, 197, 195, 194, 96, 139,
    //         248, 160, 133, 113, 182, 149, 30, 242, 40, 50, 57, 249, 139, 168, 49, 13, 5, 209, 252,
    //         26, 213, 75, 14, 95, 109, 150, 171, 161, 213, 201, 39, 51, 55, 124, 41, 137, 27, 167,
    //         145, 215, 201, 113, 59, 177, 89, 188,
    //     ];
    //     let sig = Signature::from_buffer(&buf);
    //     let res: Vec<u8> = buf.iter().map(|&x| x).collect();
    //     assert_eq!(sig.to_buffer(), res);
    //     assert_eq!(1, 2);
    // }
}
