extern crate bs58;
extern crate crypto;
extern crate secp256k1;
extern crate num_bigint as bigint;

use self::bigint::BigInt;
use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;

#[derive(Clone, Debug, Hash)]
pub struct PrivateKey {
  d: BigInt,
}

impl PrivateKey {
  pub fn new(d: BigInt) -> PrivateKey {
    PrivateKey { d }
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
}
