#![deny(
  unused_import_braces,
  unused_imports,
  unused_comparisons,
  unused_must_use,
  unused_variables,
  non_shorthand_field_patterns,
  unreachable_code,
  unused_parens
)]
extern crate bigint;
extern crate digest;
extern crate hmac_drbg;
extern crate secp256k1;
extern crate sha2;
extern crate typenum;

// For sign
use self::hmac_drbg::HmacDRBG;
use self::secp256k1::curve::ECMULT_GEN_CONTEXT;
use self::secp256k1::curve::{Affine, Jacobian, Scalar};
use self::secp256k1::{Error, Message, RecoveryId, SecretKey, Signature};
use self::sha2::Sha256;
// use self::digest::{Digest, Input};
use self::typenum::U32;

pub fn sign_raw(
  seckey: &Scalar,
  message: &Scalar,
  nonce: &Scalar,
) -> Result<(Scalar, Scalar, u8), Error> {
  let mut rp = Jacobian::default();
  // self.ecmult_gen(&mut rp, nonce);
  ECMULT_GEN_CONTEXT.ecmult_gen(&mut rp, nonce);
  let mut r = Affine::default();
  r.set_gej(&rp);
  r.x.normalize();
  r.y.normalize();
  let b = r.x.b32();
  let mut sigr = Scalar::default();
  let overflow = sigr.set_b32(&b);
  debug_assert!(!sigr.is_zero());
  debug_assert!(!overflow);

  let mut recid = (if overflow { 2 } else { 0 }) | (if r.y.is_odd() { 1 } else { 0 });

  let mut n = &sigr * seckey;
  n += message;
  let mut sigs = nonce.inv();
  sigs *= &n;
  n.clear();
  rp.clear();
  r.clear();
  if sigs.is_zero() {
    return Err(Error::InvalidMessage);
  }

  if sigs.is_high() {
    sigs = sigs.neg();
    recid = recid ^ 1;
  }
  return Ok((sigr, sigs, recid));
}

pub fn sign_new(
  message: &Message,
  seckey: &SecretKey,
  counter: &u8,
) -> Result<(Signature, RecoveryId), Error> {
  let seckey_b32 = seckey.serialize();
  let message_b32 = message.serialize();

  let mut drbg = HmacDRBG::<Sha256>::new(&seckey_b32, &message_b32, &[]);
  let mut generated = drbg.generate::<U32>(None);
  for _ in 0..*counter {
    generated = drbg.generate::<U32>(None);
  }
  let mut nonce = Scalar::default();
  // let mut nonce = Scalar::from_int(*nonce32 as u32);
  let mut overflow = nonce.set_b32(array_ref!(generated, 0, 32));
  while overflow || nonce.is_zero() {
    let generated = drbg.generate::<U32>(None);
    overflow = nonce.set_b32(array_ref!(generated, 0, 32));
  }
  let mut sec_scalar = Scalar::default();
  let _ = sec_scalar.set_b32(&seckey_b32);
  let result = 
  sign_raw(&sec_scalar, &message.0, &nonce);
  // let result = ECMULT_GEN_CONTEXT.sign_raw(&sec_scalar, &message.0, &nonce);
  #[allow(unused_assignments)]
  {
    nonce = Scalar::default();
  }
  if let Ok((sigr, sigs, recid)) = result {
    return Ok((
      Signature { r: sigr, s: sigs },
      RecoveryId::parse(recid).unwrap(),
    ));
  } else {
    return Err(result.err().unwrap());
  }
}
