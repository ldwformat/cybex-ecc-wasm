extern crate crypto;

pub mod private_key;

#[cfg(test)]
mod tests {
    use super::crypto::digest::Digest;
    use super::crypto::sha2::Sha256;
    use super::private_key::PrivateKey;
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
        let seed = "create-test12ownerqwer1234qwer1234";
        let key = PrivateKey::from_seed(seed).unwrap();
        assert_eq!("5KhczK24xDTxQvc5mmK8xnKj4yHtxz6ChWN8rQ1nQHcooJkAbbo", key.to_wif());
        // assert_eq!("5KhczK24xDTxQvc5mmK8xnKj4yHtxz6ChWN8rQ1nQHcooJkAbbo", key.to_wif());
    }
}
