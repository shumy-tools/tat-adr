use crate::crypto::{rnd_scalar};

use clear_on_drop::clear::Clear;
use core::ops::{Add, Mul, Sub};
use bls12_381::{Scalar, G2Projective};

//-----------------------------------------------------------------------------------------------------------
// Shared traits and functions for Polynomial and PointPolynomial
//-----------------------------------------------------------------------------------------------------------
fn cut_tail<Z>(v: &mut Vec::<Z>, elm: Z) where Z: Eq {
    if let Some(i) = v.iter().rev().rposition(|x| *x == elm) {
        v.truncate(i);
    }
}

fn short_mul(a: &mut Vec::<Scalar>, b: Scalar) {
    let mut prev = a[0];
    a[0] *= b;
    for v in a.iter_mut().skip(1) {
        let this = *v;
        *v = prev + *v * b;
        prev = this;
    }
    a.push(Scalar::one());
}

fn lx_num_bar(range: &[Scalar], i: usize) -> (Vec<Scalar>, Scalar) {
    let mut num = vec![Scalar::one()];
    let mut denum = Scalar::one();
    for j in 0..range.len() {
        if j != i {
            short_mul(&mut num, -range[j]);
            denum *= range[i] - range[j];
        }
    }

    (num, denum.invert().unwrap())
}

pub trait Interpolate {
    type Output;
    fn interpolate(&self) -> Self::Output;
}

pub trait Reconstruct {
    type Output;
    fn reconstruct(&self) -> Self::Output;
}

pub trait Evaluate {
    type Output;
    fn evaluate(&self, x: Scalar) -> Self::Output;
}

pub trait Degree {
    fn degree(&self) -> usize;
}

//-----------------------------------------------------------------------------------------------------------
// Share
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct Share {
    pub i: u32,
    pub yi: Scalar
}

impl Add<Share> for Share {
    type Output = Share;
    fn add(self, rhs: Share) -> Share {
        assert!(self.i == rhs.i);
        Share { i: self.i, yi: self.yi + rhs.yi }
    }
}

impl Add<Scalar> for Share {
    type Output = Share;
    fn add(self, rhs: Scalar) -> Share {
        Share { i: self.i, yi: self.yi + rhs }
    }
}

impl Sub<Share> for Share {
    type Output = Share;
    fn sub(self, rhs: Share) -> Share {
        assert!(self.i == rhs.i);
        Share { i: self.i, yi: self.yi - rhs.yi }
    }
}

impl Sub<Scalar> for Share {
    type Output = Share;
    fn sub(self, rhs: Scalar) -> Share {
        Share { i: self.i, yi: self.yi - rhs }
    }
}

impl Mul<Scalar> for Share {
    type Output = Share;
    fn mul(self, rhs: Scalar) -> Share {
        Share { i: self.i, yi: self.yi * rhs }
    }
}

impl Mul<G2Projective> for Share {
    type Output = PointShare;
    fn mul(self, rhs: G2Projective) -> PointShare {
        PointShare { i: self.i, Yi: rhs * self.yi }
    }
}

//-----------------------------------------------------------------------------------------------------------
// PointShare
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct PointShare {
    pub i: u32,
    pub Yi: G2Projective
}

impl Add<G2Projective> for PointShare {
    type Output = PointShare;
    fn add(self, rhs: G2Projective) -> PointShare {
        PointShare { i: self.i, Yi: self.Yi + rhs }
    }
}

impl Sub<G2Projective> for PointShare {
    type Output = PointShare;
    fn sub(self, rhs: G2Projective) -> PointShare {
        PointShare { i: self.i, Yi: self.Yi - rhs }
    }
}

impl Mul<Scalar> for PointShare {
    type Output = PointShare;
    fn mul(self, rhs: Scalar) -> PointShare {
        PointShare { i: self.i, Yi: self.Yi * rhs }
    }
}

//-----------------------------------------------------------------------------------------------------------
// Polynomial
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial {
    pub a: Vec<Scalar>
}

impl Drop for Polynomial {
    fn drop(&mut self) {
        for item in self.a.iter_mut() {
            item.clear();
        }
    }
}

impl Mul<Scalar> for Polynomial {
    type Output = Polynomial;
    fn mul(self, rhs: Scalar) -> Polynomial {
        Polynomial {
            a: self.a.iter().map(|ak| ak * rhs).collect::<Vec<Scalar>>()
        }
    }
}

impl Mul<G2Projective> for Polynomial {
    type Output = PointPolynomial;
    fn mul(self, rhs: G2Projective) -> PointPolynomial {
        PointPolynomial {
            A: self.a.iter().map(|ak| rhs * ak).collect::<Vec<_>>()
        }
    }
}

impl Polynomial {
    pub fn rnd(secret: Scalar, degree: usize) -> Self {
        let mut coefs = vec![secret];

        let rnd_coefs: Vec<Scalar> = (0..degree).map(|_| rnd_scalar()).collect();
        coefs.extend(rnd_coefs);

        Polynomial { a: coefs }
    }

    pub fn l_i(range: &[Scalar], i: usize) -> Scalar {
        let mut num = Scalar::one();
        let mut denum = Scalar::one();
        for j in 0..range.len() {
            if j != i {
                num *= range[j];
                denum *= range[j] - range[i];
            }
        }

        num * denum.invert().unwrap()
    }

    pub fn shares(&self, n: usize) -> ShareVector {
        let mut shares = Vec::<Share>::with_capacity(n);
        for j in 1..=n {
            let x = Scalar::from(j as u64);
            let share = Share { i: j as u32, yi: self.evaluate(x) };
            shares.push(share);
        }

        ShareVector(shares)
    }
}

impl Evaluate for Polynomial {
    type Output = Scalar;
    fn evaluate(&self, x: Scalar) -> Scalar {
        // evaluate using Horner's rule
        let mut rev = self.a.iter().rev();
        let head = *rev.next().unwrap();
            
        rev.fold(head, |partial, coef| partial * x + coef)
    }
}

impl Degree for Polynomial {
    fn degree(&self) -> usize {
        self.a.len() - 1
    }
}

//-----------------------------------------------------------------------------------------------------------
// PointPolynomial
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointPolynomial {
    pub A: Vec<G2Projective>
}

impl Mul<Scalar> for PointPolynomial {
    type Output = PointPolynomial;
    fn mul(self, rhs: Scalar) -> PointPolynomial {
        PointPolynomial {
            A: self.A.iter().map(|Ak| Ak * rhs).collect::<Vec<_>>()
        }
    }
}

impl PointPolynomial {
    pub fn verify(&self, share: &PointShare) -> bool {
        let x = Scalar::from(u64::from(share.i));
        share.Yi == self.evaluate(x)
    }
}

impl Evaluate for PointPolynomial {
    type Output = G2Projective;
    fn evaluate(&self, x: Scalar) -> G2Projective {
        // evaluate using Horner's rule
        let mut rev = self.A.iter().rev();
        let head = *rev.next().unwrap();
            
        rev.fold(head, |partial, coef| partial * x + coef)
    }
}

impl Degree for PointPolynomial {
    fn degree(&self) -> usize {
        self.A.len() - 1
    }
}

//-----------------------------------------------------------------------------------------------------------
// ShareVector
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct ShareVector(pub Vec<Share>);

impl Drop for ShareVector {
    fn drop(&mut self) {
        for item in self.0.iter_mut() {
            item.yi.clear();
        }
    }
}

impl Add<Scalar> for ShareVector {
    type Output = ShareVector;
    fn add(self, rhs: Scalar) -> ShareVector {
        let res = self.0.iter().map(|s| Share { i: s.i, yi: s.yi + rhs }).collect::<Vec<_>>();
        ShareVector(res)
    }
}

impl Mul<Scalar> for ShareVector {
    type Output = ShareVector;
    fn mul(self, rhs: Scalar) -> ShareVector {
        let res = self.0.iter().map(|s| Share { i: s.i, yi: s.yi * rhs }).collect::<Vec<_>>();
        ShareVector(res)
    }
}

impl Mul<G2Projective> for ShareVector {
    type Output = PointShareVector;
    fn mul(self, rhs: G2Projective) -> PointShareVector {
        let res = self.0.iter().map(|s| PointShare { i: s.i, Yi: rhs * s.yi }).collect::<Vec<_>>();
        PointShareVector(res)
    }
}

impl Interpolate for ShareVector {
    type Output = Scalar;
    fn interpolate(&self) -> Scalar {
        let range = self.0.iter().map(|s| Scalar::from(s.i as u64)).collect::<Vec<_>>();

        let mut acc = Scalar::zero();
        for (i, item) in self.0.iter().enumerate() {
            acc += Polynomial::l_i(&range, i) * item.yi;
        }

        acc
    }
}

//-----------------------------------------------------------------------------------------------------------
// PointShareVector
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct PointShareVector(pub Vec<PointShare>);

impl Add<G2Projective> for PointShareVector {
    type Output = PointShareVector;
    fn add(self, rhs: G2Projective) -> PointShareVector {
        let res = self.0.iter().map(|s| PointShare { i: s.i, Yi: s.Yi + rhs }).collect::<Vec<_>>();
        PointShareVector(res)
    }
}

impl Mul<Scalar> for PointShareVector {
    type Output = PointShareVector;
    fn mul(self, rhs: Scalar) -> PointShareVector {
        let res = self.0.iter().map(|s| PointShare { i: s.i, Yi: s.Yi * rhs }).collect::<Vec<_>>();
        PointShareVector(res)
    }
}

impl Interpolate for PointShareVector {
    type Output = G2Projective;

    fn interpolate(&self) -> G2Projective {
        let range = self.0.iter().map(|s| Scalar::from(s.i as u64)).collect::<Vec<_>>();

        let mut acc = G2Projective::identity();
        for (i, item) in self.0.iter().enumerate() {
            acc += item.Yi * Polynomial::l_i(&range, i);
        }

        acc
    }
}

impl Reconstruct for PointShareVector {
    type Output = PointPolynomial;

    fn reconstruct(&self) -> PointPolynomial {
        let range = self.0.iter().map(|s| Scalar::from(s.i as u64)).collect::<Vec<_>>();

        let mut acc = vec![G2Projective::identity(); range.len()];
        for (i, item) in self.0.iter().enumerate() {
            let (num, barycentric) = lx_num_bar(&range, i);
            for j in 0..num.len() {
                acc[j] += item.Yi * (num[j] * barycentric);
            }
        }

        cut_tail(&mut acc, G2Projective::identity());
        PointPolynomial { A: acc }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rnd_scalar;

    #[test]
    fn interpolation() {
        let G2 = G2Projective::generator();

        let threshold = 16;
        let parties = 3*threshold + 1;

        let s = rnd_scalar();
        let S = G2 * s;

        let poly = Polynomial::rnd(s, threshold);

        let shares = poly.shares(parties);
        let s_res = shares.interpolate();
        assert!(s == s_res);

        let S_poly = poly * G2;
        let S_shares = shares * G2;
        
        for S_sh in S_shares.0.iter() {
            assert!(S_poly.verify(S_sh) == true);
        }

        let S_res = S_shares.interpolate();
        assert!(S == S_res);
    }
}