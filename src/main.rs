#![allow(non_snake_case)]

mod crypto;
use crate::crypto::*;

use std::time::Instant;
use bls12_381::{pairing, multi_miller_loop, G1Affine, G1Projective, G2Projective, G2Affine, G2Prepared};

fn main() {
    let G1 = G1Projective::generator();
    let G2 = G2Projective::generator();
    let G2A: G2Affine = G2.into();
    let G2P: G2Prepared = G2A.into();

    let threshold = 16;
    let parties = 3*threshold + 1;

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
            //let p2 = pairing(&R.into(), &G2A) + pairing(&K_res.into(), &G2A);
            let chain: [(&G1Affine, &G2Prepared); 2] = [(&R.into(), &G2P), (&K_res.into(), &G2P)];
            let p2 = multi_miller_loop(&chain).final_exponentiation();
            assert!(p1 == p2);
        }
    
    let run = Instant::now() - start;
    println!("RUN: {:?}ms", run.as_millis());
    // G2 -> 160ms
    // G1 (pairing) -> 60ms         (1000 loops) -> 3645ms
    // G1 (miller loop) -> 57ms     (1000 loops) -> 2030ms
}
