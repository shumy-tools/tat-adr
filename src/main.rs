#![allow(non_snake_case)]

mod crypto;
use crate::crypto::*;

use std::time::Instant;
use sha2::{Sha512, Digest};
use bls12_381::{pairing, Scalar, G1Affine, G1Projective, G2Affine, G2Prepared};

/*fn thr_gen_token(yi: &ShareVector, mi: &ShareVector, k: &Scalar, R: &G1Projective, Ar: &G1Projective, Akc: &G1Projective) -> (G1Affine, G1Affine) {
    let PI = yi * R;
    let Tki = yi * Ar + mi * Akc;

    let Tk = shares.interpolate();
}*/

fn verif_token(sig: &ExtSignature, Tk: &G1Affine, M: &G1Affine, PI: &G1Affine) -> bool {
    let G2A = G2Affine::generator();
    let G2P: G2Prepared = G2A.into();

    let Mk_comp = sig.P1.to_compressed();
    let Tk_comp = Tk.to_compressed();
    let M_comp = M.to_compressed();
    let PI_comp = PI.to_compressed();

    // verification of Schnorr's signature
    let data = &[Tk_comp.as_ref(), M_comp.as_ref(), PI_comp.as_ref()];
    if !sig.verify(M, data) {
        return false
    }

    // verification of pairing signature
    let hasher = Sha512::new()
        .chain(M_comp.as_ref())    
        .chain(Mk_comp.as_ref())
        .chain(PI_comp.as_ref());

    let mut result = [0u8; 64];
    result.copy_from_slice(&hasher.result()[0..64]);

    /*let result = unsafe {
        &*(hasher.result().as_ptr() as *const [u8; 64])
    };*/
    
    let c = Scalar::from_bytes_wide(&result);
    pairing(Tk, &G2A) == multi_pairing(&[*PI, (sig.P1 * c).into()], &G2P)
}

fn main() {
    let G1 = G1Projective::generator();
    let G2A = G2Affine::generator();
    let G2P: G2Prepared = G2A.into();

    let threshold = 16;
    let parties = 2*threshold + 1;

    let start = Instant::now();
        let k = rnd_scalar();
        let K = G1 * k;

        let poly = Polynomial::rnd(k, threshold);
        let shares = poly.shares(parties);

        let r = rnd_scalar();
        let R = G1 * r;

        let RK = R + K;

        let p1 = pairing(&RK.into(), &G2A);
        let K_res = (shares * G1).interpolate();

        for _ in 0..1000 {
            let p2 = multi_pairing(&[R.into(), K_res.into()], &G2P);
            assert!(p1 == p2);
        }
    
    let run = Instant::now() - start;
    println!("RUN: {:?}ms", run.as_millis());
    // G2 -> 160ms
    // G1 (pairing) -> 60ms         (1000 loops) -> 3645ms
    // G1 (miller loop) -> 57ms     (1000 loops) -> 2030ms
}
