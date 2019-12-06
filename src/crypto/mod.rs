use rand::{thread_rng, Rng};
use bls12_381::{multi_miller_loop, Scalar, G1Affine, G2Prepared, Gt};

mod macros;
pub use crate::crypto::macros::*;

mod shares;
pub use crate::crypto::shares::*;

mod signatures;
pub use crate::crypto::signatures::*;

pub fn rnd_scalar() -> Scalar {
    let mut arr = [0u8; 64];
    thread_rng().fill(&mut arr);
    Scalar::from_bytes_wide(&arr)
}

pub fn multi_pairing(points: &[G1Affine], base: &G2Prepared) -> Gt {
    let chain: Vec<(&G1Affine, &G2Prepared)> = points.iter().map(|p| (p, base)).collect::<Vec<_>>();
    multi_miller_loop(&chain).final_exponentiation()
}