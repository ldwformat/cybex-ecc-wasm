extern crate bs58;
extern crate crypto;
extern crate num_bigint as bigint;
extern crate secp256k1;

use self::crypto::digest::Digest;
use self::crypto::ripemd160::Ripemd160;
use self::secp256k1::{PublicKey as Q, Secp256k1, SecretKey};

#[derive(Clone, Debug)]
pub struct PublicKey {
  q: Q,
}

impl PublicKey {
  pub fn from_buffer(buffer: &[u8]) -> PublicKey {
    let secp = Secp256k1::without_caps();
    let q = Q::from_slice(&secp, &buffer).unwrap();
    PublicKey { q }
  }

  pub fn from_secret(sk: &SecretKey) -> PublicKey {
    let secp = Secp256k1::new();
    let q = Q::from_secret_key(&secp, &sk);
    PublicKey { q }
  }

  pub fn to_buffer(&self) -> [u8; 33] {
    self.q.serialize()
  }

  pub fn to_string(&self) -> String {
    let mut pub_buf = Vec::from(&self.to_buffer()[..]);
    let mut ripemd160 = Ripemd160::new();
    ripemd160.input(&pub_buf[..]);
    let mut checksum_result = [0; 20];
    ripemd160.result(&mut checksum_result);
    pub_buf.extend(&checksum_result[..4]);
    bs58::encode(pub_buf).into_string()
  }
}
