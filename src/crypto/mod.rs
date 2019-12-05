use rand::{thread_rng, Rng};
use bls12_381::Scalar;

mod shares;
pub use crate::crypto::shares::*;

pub fn rnd_scalar() -> Scalar {
    let mut arr = [0u8; 64];
    thread_rng().fill(&mut arr);
    Scalar::from_bytes_wide(&arr)
}