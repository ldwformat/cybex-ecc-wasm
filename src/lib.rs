extern crate crypto;
extern crate hex_d_hex;
extern crate num_bigint as bigint;

pub mod private_key;
pub mod public_key;
pub mod signature;
// pub mod ecurve;
// pub mod ecsignature;
// pub mod ecdsa;

#[cfg(test)]
mod tests {
    use super::bigint::BigInt;
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
        let third = "thirdteststr";
        let forth = "forthteststr";
        let seed = "hereisasimpletestseed";
        let tx = "59e27e3883fc5ec4dbff68855f83961303157df9a64a3ecf49982affd8e8d4907c62134ce2503fb1be5b0100d0070000000000000012950680841e000000000000000000";
        let tx_buffer = &*hex_d_hex::dhex(tx);
        let sk = PrivateKey::from_seed(&seed).unwrap().secret_key;
        let signature3 = Signature::sign_buffer(third.as_bytes(), &sk).to_hex();
        println!(
            "Third: {}",
            &*hex_d_hex::lower_hex(&Vec::from(third.as_bytes()))
        );
        assert_eq!(signature3, "1f120b8e8af00b06b52dabdee8d06dfc1e972b70ca59ba2e3d1204a1361076d7240141a346941b3c4048e533a6ea01a9423c18c0884519d047f1126f262ec9cd17");
        let signature4 = Signature::sign_buffer(forth.as_bytes(), &sk).to_hex();
        println!(
            "Forth {}",
            &*hex_d_hex::lower_hex(&Vec::from(forth.as_bytes()))
        );
        assert_eq!(signature4, "2055ea9680ce3496f5f68c0e3b8c31964b180df34eb2d343cd2002cd2c22196057241ccffd9c99f62e65d06efc6d885d8e509dff49af5ff650daad2b75ff793b9c");
    }

    #[test]
    fn bignum_test() {
        let origin_num: &str = "ff";
        let bg = BigInt::parse_bytes(origin_num.as_bytes(), 16).unwrap();
        // bg.add(2);
        assert_eq!(bg.to_str_radix(10), "255");
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
