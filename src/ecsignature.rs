extern crate crypto;
extern crate hex_d_hex;
// use std::convert::TryInto;
use ::bigint::BigInt;
pub struct ECSignature {
  r: BigInt,
  s: BigInt,
}

impl ECSignature {
  pub fn new(r: BigInt, s: BigInt) -> ECSignature {
    ECSignature { r, s }
  }

  pub fn to_compact(&self, i: usize, compressed: bool) -> Vec<u8> {
    let i = if compressed { i + 31 } else { i + 27 };

    let mut buf: Vec<u8> = Vec::new();
    buf.push(i as u8);
    buf.extend(self.r.to_signed_bytes_be());
    buf.extend(self.s.to_signed_bytes_be());
    buf
  }

  pub fn to_der(&self) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&[0x02, self.r.to_signed_bytes_be().len() as u8]);
    buf.extend(self.r.to_signed_bytes_be());
    buf.extend_from_slice(&[0x02, self.s.to_signed_bytes_be().len() as u8]);
    buf.extend(self.s.to_signed_bytes_be());
    buf.insert(0, 0x30);
    let l = buf.len() as u8;
    buf.insert(0, l);
    buf
  }
}
