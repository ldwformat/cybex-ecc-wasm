use super::num_traits::{One, Zero};
use bigint::BigInt;
use bigint::Sign::Minus;
use ecurve::point::Point;

pub struct Curve {
  pub p: BigInt,
  pub a: BigInt,
  pub b: BigInt,
  pub n: BigInt,
  pub h: BigInt,
  pub Gx: BigInt,
  pub Gy: BigInt,
}

impl Curve {
  pub fn new(
    &self,
    p: BigInt,
    a: BigInt,
    b: BigInt,
    Gx: BigInt,
    Gy: BigInt,
    n: BigInt,
    h: BigInt,
  ) -> Curve {
    Curve {
      p,
      a,
      b,
      Gx,
      Gy,
      n,
      h,
    }
  }

  // pub fn infinity(&self) -> Point {
  //   Point::new(*self, Nil, Nil, 0.to_bigint().unwrap)
  // }

  pub fn p_over_four(&self) -> BigInt {
    (self.p + BigInt::from(1)) >> 2
  }

  pub fn p_length(&self) -> usize {
    ((self.p.to_signed_bytes_le().len() / 8 + 7) / 8)
  }

  pub fn G(&self) -> Point {
    Point::from_affine(self, self.Gx, self.Gy)
  }

  pub fn point_from_x(&self, is_odd: bool, x: BigInt) -> Point {
    let alpha = (x.modpow(&BigInt::from(3), &BigInt::from(1)) + (self.a * x) + (self.b)) % self.p;
    let mut beta = alpha.modpow(&self.p_over_four(), &self.p);
    let y = if (beta % 2 == Zero::zero()) ^ !is_odd {
      self.p - beta
    } else {
      beta
    };
    Point::from_affine(self, x, y)
  }

  pub fn is_on_curve(&self, Q: Point) -> bool {
    let x = Q.affine_x();
    let y = Q.affine_y();
    let a = self.a;
    let b = self.b;
    let p = self.p;

    if x.sign() == Minus || x >= p {
      return false;
    }

    if y.sign() == Minus || y >= p {
      return false;
    }

    let lhs = y.modpow(&BigInt::from(-2), &p);
    let rhs = (x.modpow(&BigInt::from(3), &One::one()) + (a * x) + b) % p;

    lhs == rhs
  }
}
