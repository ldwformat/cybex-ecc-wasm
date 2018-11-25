extern crate base58;
extern crate sha2;
extern crate ripemd160;
extern crate bigint;
extern crate secp256k1;

use self::base58::ToBase58;
use self::ripemd160::{Digest, Ripemd160};
use self::secp256k1::{PublicKey as Q, SecretKey};

#[derive(Clone, Debug)]
pub struct PublicKey {
  q: Q,
}

impl PublicKey {
  pub fn from_buffer(buffer: &[u8]) -> PublicKey {
    let q = Q::parse_slice(&buffer, Some(true)).unwrap();
    PublicKey { q }
  }

  pub fn from_secret(sk: &SecretKey) -> PublicKey {
    let q = Q::from_secret_key(&sk);
    PublicKey { q }
  }

  pub fn to_buffer(&self) -> [u8; 33] {
    self.q.serialize_compressed()
  }

  pub fn to_string(&self) -> String {
    let mut pub_buf = Vec::from(&self.to_buffer()[..]);
    let mut ripemd160 = Ripemd160::new();
    ripemd160.input(&pub_buf[..]);
    // let mut checksum_result = [0; 20];
    // let checksum_result = ripemd160.result()[..20];
    pub_buf.extend(&ripemd160.result()[..4]);
    pub_buf.as_slice().to_base58()
  }
}
