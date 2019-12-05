#![allow(non_snake_case)]

mod crypto;
use crate::crypto::*;

use bls12_381::{pairing, G1Projective, G2Projective};

fn main() {
    let G1 = G1Projective::generator();
    let G2 = G2Projective::generator();

    let threshold = 16;
    let parties = 3*threshold + 1;

    let k = rnd_scalar();
    let K2 = G2 * k;

    let poly = Polynomial::rnd(k, threshold);
    let shares = poly.shares(parties);

    let r = rnd_scalar();
    let R2 = G2 * r;

    let RK2 = R2 + K2;

    let p1 = pairing(&G1.into(), &RK2.into());

    let K2_res = (shares * G2).interpolate();
    let p2 = pairing(&G1.into(), &R2.into()) + pairing(&G1.into(), &K2_res.into());
    assert!(p1 == p2);
    println!("OK");
}
