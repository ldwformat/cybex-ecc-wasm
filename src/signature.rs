extern crate crypto;
extern crate hex_d_hex;
extern crate num_bigint as bigint;
extern crate secp256k1;
// use std::convert::TryInto;
use self::bigint::BigInt;
use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;
use self::secp256k1::{Message, Secp256k1, SecretKey, Signature as Signer};

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
    let r = BigInt::from_signed_bytes_le(&buf[1..33]);
    let s = BigInt::from_signed_bytes_le(&buf[33..]);
    Signature { r, s, i }
  }

  pub fn from_hex(hex_str: &str) -> Signature {
    Signature::from_buffer(&*hex_d_hex::dhex(hex_str))
  }

  pub fn to_buffer(&self) -> Vec<u8> {
    let mut buf = vec![self.i];
    buf.extend(&self.r.to_signed_bytes_le());
    buf.extend(&self.s.to_signed_bytes_le());
    buf
  }

  pub fn to_hex(&self) -> String {
    *hex_d_hex::lower_hex(&self.to_buffer())
  }

  fn ecsign(buffer: &[u8], nonce: u8, sk: SecretKey) -> Signer {
    let mut buffer_to_sign: Vec<u8> = buffer.iter().map(|&x| x).collect();
    buffer_to_sign.push(nonce);
    let signer = Secp256k1::signing_only();
    let mut encoder = Sha256::new();
    encoder.input(buffer_to_sign.as_slice());
    let mut to_sign: [u8; 32] = [0; 32];
    encoder.result(&mut to_sign);
    println!("Final To Sign: {:x?}", to_sign);
    let msg = Message::from_slice(&to_sign).unwrap();
    signer.sign(&msg, &sk)
  }

  pub fn sign_buffer(buffer: &[u8], sk: SecretKey) -> Signature {
    let mut encoder = Sha256::new();
    let mut buffer_sha2 = [0u8; 32];
    encoder.input(&buffer);
    encoder.result(&mut buffer_sha2);
    let signer = Secp256k1::signing_only();
    println!("Buffer Sha2: {:x?}", buffer_sha2);
    let mut der: Vec<u8> = Vec::new();
    let mut ecsignature: Signer;
    let mut len_r;
    let mut len_s;
    let mut i;
    let mut e = BigInt::from_signed_bytes_le(&buffer_sha2);
    let mut nonce = 0;

    loop {
      ecsignature = Signature::ecsign(&buffer_sha2, nonce, sk);
      ecsignature.normalize_s(&signer);
      der = ecsignature.serialize_der(&signer);
      len_r = der[3];
      len_s = der[5 + len_r as usize];
      println!("ESIGN: {:?}", ecsignature);
      println!("DER: {:?}", der);
      if len_r == 32 && len_s == 32 {
        i = 0;
        i += 4; // compressed
        i += 27; // compact  //  24 or 27 :( forcing odd-y 2nd key candidate)
        break;
      }
      nonce = nonce + 1;
    }
    let (r, s) = Signature::decode_der(der);

    Signature { r, s, i }
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
    println!("S HEX: {:? }", sb);
    assert_eq!(der_buffer.len(), offset, "Invalid DER encoding");
    (
      BigInt::from_signed_bytes_le(&rb),
      BigInt::from_signed_bytes_le(&sb),
    )
  }
}
