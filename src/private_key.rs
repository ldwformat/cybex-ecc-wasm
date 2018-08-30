extern crate bs58;
extern crate crypto;
extern crate num_bigint as bigint;
extern crate secp256k1;

use public_key::PublicKey;
use self::bigint::BigInt;
use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;
use self::secp256k1::{Secp256k1, SecretKey};

#[derive(Clone, Debug)]
pub struct PrivateKey {
  d: BigInt,
  pub secret_key: SecretKey,
  pub public_key: PublicKey,
}

impl PrivateKey {
  pub fn new(d: BigInt) -> PrivateKey {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&secp, &d.to_signed_bytes_le()).unwrap();
    let public_key = PublicKey::from_secret(&secret_key);
    PrivateKey {
      d,
      secret_key,
      public_key,
    }
  }

  pub fn from_seed(seed: &str) -> Result<PrivateKey, &'static str> {
    let mut sha2 = Sha256::new();
    sha2.input_str(seed);
    let mut seed_vec: [u8; 32] = [0; 32];
    sha2.result(&mut seed_vec);
    PrivateKey::from_buffer(&seed_vec)
  }

  pub fn from_buffer(buffer: &[u8]) -> Result<PrivateKey, &'static str> {
    if buffer.len() != 32 {
      println!("WARN: Expecting 32 bytes, instead got {}", buffer.len());
    }
    if buffer.len() == 0 {
      return Err("Empty buffer");
    }
    Ok(PrivateKey::new(BigInt::from_signed_bytes_le(buffer)))
  }

  pub fn to_wif(&self) -> String {
    let mut private_key = self.to_buffer();
    private_key.insert(0, 0x80u8);
    let mut checksum = Sha256::new();
    let mut checksum_result: [u8; 32] = [0; 32];
    checksum.input(private_key.as_ref());
    checksum.result(&mut checksum_result);
    checksum.reset();
    checksum.input(&checksum_result);
    checksum.result(&mut checksum_result);
    private_key.extend(&checksum_result[0..4]);
    bs58::encode(private_key).into_string()
  }

  pub fn to_buffer(&self) -> Vec<u8> {
    self.d.to_signed_bytes_le()
  }


  // pub fn toPublicKeyPoint(&self)
}
