extern crate num_bigint as bigint;
use self::bigint::BigInt;
extern crate hex_d_hex;

pub struct Secp256k1Curve {
  pub p: BigInt,
  pub a: BigInt,
  pub b: BigInt,
  pub n: BigInt,
  pub h: BigInt,
  pub Gx: BigInt,
  pub Gy: BigInt,
}

impl Secp256k1Curve {
  pub fn new() -> Secp256k1Curve {
    let p = BigInt::parse_bytes(
      b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
      16,
    ).unwrap();
    let a = BigInt::parse_bytes(b"00", 16).unwrap();
    let b = BigInt::parse_bytes(b"07", 16).unwrap();
    let n = BigInt::parse_bytes(
      b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
      16,
    ).unwrap();
    let h = BigInt::parse_bytes(b"01", 16).unwrap();
    let Gx = BigInt::parse_bytes(
      b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      16,
    ).unwrap();
    let Gy = BigInt::parse_bytes(
      b"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
      16,
    ).unwrap();
    Secp256k1Curve {
      p,
      a,
      b,
      n,
      h,
      Gx,
      Gy,
    }
  }
}
