use crate::private_key::PrivateKey;
use crate::public_key::PublicKey;

use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes256;

use secp256k1::SharedSecret;
use sha2::{Digest, Sha256, Sha512};

pub struct Memo {
  pub from: String,
  pub to: String,
  pub nonce: u64,
  pub message: String,
}

impl Memo {
  pub fn encrypt_message(
    private_key: &PrivateKey,
    public_key: &PublicKey,
    msg: &str,
    nonce: u64,
  ) -> Vec<u8> {
    let shared_secret = private_key.get_shared_secret(&public_key);
    // println!("S: {:0x?}", &shared_secret);
    let seed = format!(
      "{}{}",
      nonce.to_string(),
      hex_d_hex::lower_hex(&shared_secret)
    );
    let aes = crate::aes::Aes::from_seed(Some(&seed)).unwrap();
    let mut sha2 = Sha256::new();
    sha2.input(&msg.as_bytes());
    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&sha2.result()[0..4]);

    let mut plain_text = Vec::new();
    plain_text.extend(&checksum);
    plain_text.extend(msg.as_bytes());
    // println!("PlainWords: {:0x?}", plain_text);
    aes_frast::padding_128bit::pa_pkcs7(&mut plain_text);
    let mut cipher_text: Vec<u8> = vec![0u8; plain_text.len()];
    let mut w_keys: Vec<u32> = vec![0u32; 60];
    aes_frast::aes_core::setkey_enc_auto(&aes.key.unwrap(), &mut w_keys);
    aes_frast::aes_with_operation_mode::cbc_enc(
      &plain_text,
      &mut cipher_text,
      &w_keys,
      &aes.iv.unwrap(),
    );
    cipher_text
  }

  pub fn get_message(&self, private_key: &PrivateKey, pub_str: &str) -> String {
    let public_key = PublicKey::from_string(pub_str, None);
    let shared_secret = SharedSecret::new(&public_key.q, &private_key.secret_key).unwrap();
    let mut sha = Sha512::new();
    let mut nonce_plus_secret: Vec<u8> = Vec::new();
    println!("S: {:?}", shared_secret.as_ref());
    println!("Nonce: {:?}", self.nonce.to_string());
    nonce_plus_secret.extend(self.nonce.to_string().as_bytes());
    nonce_plus_secret.extend(shared_secret.as_ref());
    sha.input(&nonce_plus_secret);
    let secret = sha.result()[..].iter().cloned().collect();
    let message_buf = *hex_d_hex::dhex(&self.message);
    println!("Msg: {:?}", message_buf);
    Memo::aes_decrypt(&secret, &message_buf)
    // Memo::aes_decrypt(&secret, &self.message.as_bytes().iter().cloned().collect())
  }

  pub fn aes_decrypt(key_sha512: &Vec<u8>, cipher_text: &Vec<u8>) -> String {
    println!("Size: {}", cipher_text.len());
    let plain_len = cipher_text.len();
    let aes = crate::aes::Aes::from_sha512(&*hex_d_hex::lower_hex(&key_sha512)).unwrap();
    let mut w_keys: Vec<u32> = vec![0u32; 60];
    let mut plain_text = vec![0u8; plain_len];
    aes_frast::aes_core::setkey_enc_auto(&aes.key.unwrap(), &mut w_keys);
    println!("Key: {:?}", w_keys);
    aes_frast::aes_with_operation_mode::cbc_dec(
      &cipher_text[..],
      &mut plain_text,
      &w_keys,
      &aes.iv.unwrap(),
    );
    // aes_frast::padding_128bit::drop_last_block(&mut plain_text);
    println!("RES: {:?}", plain_text);
    (*String::from_utf8_lossy(&plain_text)).to_string()
  }
}
