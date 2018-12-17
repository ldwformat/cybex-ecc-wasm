use base58::{ToBase58, FromBase58};
use ripemd160::{Digest, Ripemd160};
use secp256k1::{PublicKey as Q, SecretKey};

#[derive(Clone, Debug)]
pub struct PublicKey {
  pub q: Q,
}

impl PublicKey {
  pub fn from_buffer(buffer: &[u8]) -> PublicKey {
    let q = Q::parse_slice(&buffer, Some(true)).unwrap();
    PublicKey { q }
  }

  pub fn from_string(pub_str: &str, prefix: Option<&str>) -> PublicKey {
    let pub_str = match prefix {
      Some(prefix) => pub_str.replace(prefix, ""),
      None => String::from(pub_str)
    };

    let pub_buf: Vec<u8> = pub_str.from_base58().unwrap();
    let checksum = &pub_buf[pub_buf.len() - 4..];
    let pubkey = &pub_buf[0..pub_buf.len() - 4];
    let mut ripemd160 = Ripemd160::new();
    ripemd160.input(&pubkey);
    let mut new_checksum: [u8; 4] = [0; 4];
    new_checksum.copy_from_slice(&ripemd160.result()[..4]);

    assert_eq!(new_checksum, checksum);
    PublicKey::from_buffer(pubkey)
  }

  pub fn from_secret(sk: &SecretKey) -> PublicKey {
    let q = Q::from_secret_key(&sk);
    PublicKey { q }
  }

  pub fn to_buffer(&self) -> [u8; 33] {
    self.q.serialize_compressed()
  }

  pub fn to_string(&self, prefix: Option<&str>) -> String {
    let mut pub_buf = Vec::from(&self.to_buffer()[..]);
    let mut ripemd160 = Ripemd160::new();
    ripemd160.input(&pub_buf[..]);
    pub_buf.extend(&ripemd160.result()[..4]);
    let main = pub_buf.as_slice().to_base58();
    match prefix {
      Some(prefix) => format!("{}{}", prefix, main),
      None => main
    }
  }
}
