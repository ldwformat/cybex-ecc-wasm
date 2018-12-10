extern crate base58;
extern crate bigint;
extern crate secp256k1;
extern crate sha2;

use self::base58::ToBase58;
use self::secp256k1::SecretKey;
use self::sha2::{Digest, Sha256};
use bigint::U256 as BigInt;
use public_key::PublicKey;

#[derive(Clone, Debug)]
pub struct PrivateKey {
  d: BigInt,
  pub secret_key: SecretKey,
  pub public_key: PublicKey,
}

impl PrivateKey {
  pub fn new(d: BigInt) -> PrivateKey {
    // let secp = Secp256k1::new();
    let mut buf: [u8; 32] = [0; 32];
    d.to_big_endian(&mut buf);
    let secret_key = SecretKey::parse_slice(&buf).unwrap();
    let public_key = PublicKey::from_secret(&secret_key);
    // println!("D: {:?}", buf);
    PrivateKey {
      d,
      secret_key,
      public_key,
    }
  }

  pub fn from_seed(seed: &str) -> Result<PrivateKey, &'static str> {
    let mut sha2 = Sha256::new();
    sha2.input(seed.as_bytes());
    // sha2.input_str(seed);
    let mut seed_vec: [u8; 32] = [0; 32];
    seed_vec.copy_from_slice(&sha2.result()[..]);
    PrivateKey::from_buffer(&seed_vec)
  }

  pub fn from_buffer(buffer: &[u8]) -> Result<PrivateKey, &'static str> {
    if buffer.len() != 32 {
      println!("WARN: Expecting 32 bytes, instead got {}", buffer.len());
    }
    if buffer.len() == 0 {
      return Err("Empty buffer");
    }
    // println!("Big: {:?}", BigInt::from(buffer));
    Ok(PrivateKey::new(BigInt::from(buffer)))
  }

  pub fn to_wif(&self) -> String {
    let mut private_key = self.to_buffer();
    private_key.insert(0, 0x80u8);
    let mut checksum = Sha256::new();
    let mut checksum_result: [u8; 32] = [0; 32];
    checksum.input(&private_key);
    checksum_result.copy_from_slice(&checksum.result()[..]);
    // checksum.result(&mut checksum_result);
    checksum = Sha256::new();
    checksum.input(&checksum_result);
    checksum_result.copy_from_slice(&checksum.result()[..]);
    // checksum.result(&mut checksum_result);
    private_key.extend(&checksum_result[0..4]);
    private_key.as_slice().to_base58()
  }

  pub fn to_buffer(&self) -> Vec<u8> {
    let mut buf: [u8; 32] = [0; 32];
    self.d.to_big_endian(&mut buf);
    buf.iter().cloned().collect()
  }

  // pub fn toPublicKeyPoint(&self)
}
