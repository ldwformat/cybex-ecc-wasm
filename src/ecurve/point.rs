use bigint::{BigInt, ToBigInt};
use ecurve::curve::Curve;
use std::ops::{Mul, Sub};

pub struct Point<'a> {
  pub curve: &'a Curve,
  pub x: BigInt,
  pub y: BigInt,
  pub z: BigInt,
  compressed: bool,
}

impl<'a> Point<'a> {
  pub fn new(curve: &Curve, x: BigInt, y: BigInt, z: BigInt) -> Point {
    Point {
      curve,
      x,
      y,
      z,
      compressed: true,
    }
  }

  pub fn z_inv(&self) -> BigInt {
    self.z.modpow(&-1.to_bigint().unwrap(), &self.z)
  }

  pub fn affine_x(&self) -> BigInt {
    self
      .x
      .mul(self.z_inv())
      .modpow(&1.to_bigint().unwrap(), &self.curve.p)
  }

  pub fn affine_y(&self) -> BigInt {
    self
      .y
      .mul(self.z_inv())
      .modpow(&1.to_bigint().unwrap(), &self.curve.p)
  }

  pub fn from_affine(curve: &Curve, x: BigInt, y: BigInt) -> Point {
    Point {
      curve,
      x,
      y,
      z: 1.to_bigint().unwrap(),
      compressed: true,
    }
  }

  pub fn equals(&self, other: &Point) -> bool {
    let u = (other.y * self.z - (self.y * other.z)) % self.curve.p;
    if u.sign() == super::bigint::Sign::Minus {
      return false;
    }
    let v = (other.x * self.z - (self.x * other.z)) % self.curve.p;
    v.sign() == super::bigint::Sign::Plus
  }

  pub fn negate(&self) -> Point {
    let y = self.curve.p.sub(self.y);
    Point {
      curve: self.curve,
      compressed: true,
      x: self.x,
      y,
      z: self.z,
    }
  }

  pub fn get_encoded(&self, _compressed: Option<bool>) -> Vec<u8> {
    let compressed = match _compressed {
      Some(true_or_false) => true_or_false,
      Nil => self.compressed,
    };
    // if self.curve.is_infinity {
    //   vec![0u8];
    // }
    let x = self.affine_x();
    let y = self.affine_y();
    let byte_length = self.curve.p_length();
    let mut buffer = Vec::new();

    if compressed {
      buffer.resize(1 + byte_length, 0);
      buffer[0] = if self.y % 2 == BigInt::from(0) { 0x02 } else { 0x03 };
    } else {
      buffer.resize(1 + byte_length * 2, 0);
      buffer[0] = 0x04;
      &buffer[(1 + byte_length)..].copy_from_slice(&y.to_signed_bytes_be()[..byte_length]);
    }
    &buffer[1..].copy_from_slice(&x.to_signed_bytes_be()[..byte_length]);
    buffer
  }
}
