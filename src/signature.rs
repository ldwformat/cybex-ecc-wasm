#![no_std]
extern crate bigint;
extern crate hex_d_hex;

extern crate secp256k1;
extern crate sha2;
use ecdsa;
// #[macro_use]
// extern crate arrayref;

//
// use std::convert::TryInto;
use self::bigint::U256 as BigInt;
use self::secp256k1::{sign, Message, RecoveryId, SecretKey, Signature as Signer};
use self::sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct Signature {
  pub r: BigInt,
  pub s: BigInt,
  pub i: u8,
}

impl Signature {
  pub fn from_buffer(buf: &[u8]) -> Signature {
    assert_eq!(buf.len(), 65, "Invalid signature length");
    let i = buf[0];
    assert_eq!(i - 27, (i - 27) & 7, "Invalid signature parameter");
    let r = BigInt::from(&buf[1..33]);
    let s = BigInt::from(&buf[33..]);
    Signature { r, s, i }
  }

  pub fn from_hex(hex_str: &str) -> Signature {
    Signature::from_buffer(&*hex_d_hex::dhex(hex_str))
  }

  pub fn to_buffer(&self) -> Vec<u8> {
    let mut buf = vec![self.i];
    let mut buf_r: [u8; 32] = [0; 32];
    let mut buf_s: [u8; 32] = [0; 32];
    &self.r.to_big_endian(&mut buf_r);
    &self.s.to_big_endian(&mut buf_s);
    buf.extend(buf_r.iter());
    buf.extend(buf_s.iter());
    buf
  }

  pub fn to_hex(&self) -> String {
    *hex_d_hex::lower_hex(&self.to_buffer())
  }

  fn ecsign(buffer: &[u8], sk: &SecretKey, counter: &u8) -> (Signer, RecoveryId) {
    let mut to_be = [0u8; 32];
    to_be.copy_from_slice(buffer);
    let msg = Message::parse(&to_be);
    println!("Buffer Sha256: {:0x?}", &to_be);
    // sign(&msg, &sk).unwrap()
    ecdsa::sign_new(&msg, &sk, counter).unwrap()
  }

  pub fn is_canonical(sig: Vec<u8>) -> bool {
    let sig = sig.as_slice();
    println!("{:?}", sig);
    // true
    !((sig[1] & 0x80) != 0)
      && !(sig[1] == 0 && !((sig[2] & 0x80) != 0))
      && !((sig[33] & 0x80) != 0)
      && !(sig[33] == 0 && !((sig[34] & 0x80) != 0))
  }

  pub fn sign_buffer(buffer: &[u8], sk: &SecretKey) -> Signature {
    let mut encoder = Sha256::new();
    let mut buffer_sha2 = [0u8; 32];
    encoder.input(&buffer);
    // encoder.result(&mut buffer_sha2);
    buffer_sha2.copy_from_slice(&encoder.result().as_slice());
    let mut signature: Signature;
    let mut counter = 0;
    loop {
      let (ecsignature, _i) = Signature::ecsign(&buffer_sha2, &sk, &counter);
      let mut i = _i.into();
      i += 27;
      i += 4;
      // println!("--------------------------");
      // println!("Force Low R {:x?}", ecsignature.r.b32());
      // println!("Force Low S {:x?}", ecsignature.s.b32());
      // println!("--------------------------");
      let (r, s) = (ecsignature.r, ecsignature.s);

      let s = Signature {
        r: BigInt::from(&r.b32()[..]),
        s: BigInt::from(&s.b32()[..]),
        i,
      };
      if Signature::is_canonical(s.to_buffer()) {
        signature = s;
        break;
      }
      counter += 1;
    }
    signature
  }

  pub fn sign_hex(hex: &str, sk: &SecretKey) -> Signature {
    Signature::sign_buffer(&*hex_d_hex::dhex(hex), sk)
  }

  fn decode_der(der_buffer: Vec<u8>) -> (BigInt, BigInt) {
    assert_eq!(der_buffer[0], 0x30, "Not a DER sequence");
    assert_eq!(
      der_buffer[1] as usize,
      der_buffer.len() - 2,
      "Invalid sequence length"
    );
    assert_eq!(der_buffer[2], 0x02, "Expected a DER integer");

    let r_len = der_buffer[3];
    assert!(r_len > 0, "R length is zero");

    let mut offset: usize = 4 + r_len as usize;
    assert_eq!(der_buffer[offset], 0x02, "Expected a DER integer(2)");

    let s_len = der_buffer[offset + 1];
    assert!(s_len > 0, "S length is zero");

    let (rb, sb) = (&der_buffer[4..offset], &der_buffer[offset + 2..]);

    offset = offset + s_len as usize + 2;

    if r_len > 1 && rb[0] == 0x00 {
      assert!(rb[1] & 0x80 > 0, "R value excessively padded");
    }
    if s_len > 1 && sb[0] == 0x00 {
      assert!(sb[1] & 0x80 > 0, "R value excessively padded");
    }
    println!("S HEX: {:0x? }", sb);
    assert_eq!(der_buffer.len(), offset, "Invalid DER encoding");
    (BigInt::from(rb), BigInt::from(sb))
  }
}
