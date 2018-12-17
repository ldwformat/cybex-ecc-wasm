use crate::private_key::PrivateKey;
use crate::public_key::PublicKey;

// use aes::block_cipher_trait::generic_array::GenericArray;
// use aes::block_cipher_trait::BlockCipher;
// use aes::Aes256;

use secp256k1::SharedSecret;
use sha2::{Digest, Sha256, Sha512};

pub struct Aes {
  pub iv: Option<[u8; 16]>,
  pub key: Option<[u8; 32]>,
}

impl Aes {
  pub fn new(iv: [u8; 16], key: [u8; 32]) -> Aes {
    Aes {
      iv: Some(iv),
      key: Some(key),
    }
  }

  pub fn clean(mut self) {
    self.iv = None;
    self.key = None;
  }

  //
  pub fn from_seed(seed: Option<&str>) -> Result<Aes, String> {
    match seed {
      None => Err(String::from("Seed is required")),
      Some(seed) => {
        let mut encoder = Sha512::new();
        encoder.input(seed.as_bytes());
        let hex = *hex_d_hex::lower_hex(&encoder.result()[..].iter().cloned().collect());
        Aes::from_sha512(&hex)
      }
    }
  }

  pub fn from_sha512(hash: &str) -> Result<Aes, String> {
    match hash.len() {
      128 => {
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&*hex_d_hex::dhex(&hash[64..96]).as_slice());
        let mut key = [0u8; 32];
        key.copy_from_slice(&*hex_d_hex::dhex(&hash[0..64]).as_slice());
        Ok(Aes::new(iv, key))
      }
      _ => Err(format!(
        "A Sha512 in HEX should be 128 characters long, instead got {}",
        hash.len()
      )),
    }
  }

  // pub fn from_buffer(buf: &[u8]) -> Result<Aes, String> {
  //   match buf.len() {
  //     64 => {
  //       let mut hash = Vec::with_capacity(128);
  //       hash.clone_from_slice(buf);
  //       Ok(Aes::from_sha512(&hash[..]).unwrap())
  //       // Ok(Aes::from_sha512(&*hex_d_hex::lower_hex(&hash)).unwrap())
  //     }
  //     _ => Err(format!(
  //       "A Sha512 Buffer should be 64 characters long, instead got {}",
  //       buf.len()
  //     )),
  //   }
  // }

  pub fn decrypt_word_array(&self, cipher_array: &[u8]) -> String {
    let mut key = [0u32; 32];
    let k = &self.key.unwrap()[..];
    for i in 0..32 {
      key[i] = k[i] as u32
    }
    let iv = self.iv.unwrap();

    let mut plain = [0u8; 256];
    aes_frast::aes_with_operation_mode::cbc_dec(cipher_array, &mut plain, &key[..], &iv[..]);

    let res = (*String::from_utf8_lossy(&plain[..])).to_string();
    println!("{:?}", res);
    res
  }

  pub fn decrypt_with_checksum(
    priv_key: &PrivateKey,
    public_key_str: &str,
    nonce: Option<&str>,
    message: &str,
  ) -> String {
    let nonce = match nonce {
      Some(n) => n,
      None => "",
    }
    .as_bytes();
    let message_buf = *hex_d_hex::dhex(message);
    let s = SharedSecret::new(
      &PublicKey::from_string(public_key_str, None).q,
      &priv_key.secret_key,
    )
    .unwrap();

    let mut seed: Vec<u8> = Vec::new();
    seed.extend(nonce);
    seed.extend(s.as_ref());
    println!("Get Aes Instance: {:?}", seed);
    let aes_instance = Aes::from_seed(Some(&*String::from_utf8_lossy(&seed[..]))).unwrap();
    println!("Got Aes Instance");
    aes_instance.decrypt_word_array(&message_buf)
  }

  
}
