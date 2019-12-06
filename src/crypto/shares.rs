#![allow(dead_code)]

use crate::crypto::{rnd_scalar};

use clear_on_drop::clear::Clear;
use core::ops::{Add, Mul, Sub};
use bls12_381::{Scalar, G1Projective};

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
#[derive(Debug, Copy, Clone)]
pub struct Share {
    pub i: u32,
    pub yi: Scalar
}

define_add_variants!(LHS = Share, RHS = Share, Output = Share);
impl<'a, 'b> Add<&'b Share> for &'a Share {
    type Output = Share;
    fn add(self, rhs: &'b Share) -> Share {
        assert!(self.i == rhs.i);
        Share { i: self.i, yi: self.yi + rhs.yi }
    }
}

define_add_variants!(LHS = Share, RHS = Scalar, Output = Share);
define_add_variants!(LHS = Scalar, RHS = Share, Output = Share);
define_comut_add!(LHS = Scalar, RHS = Share, Output = Share);
impl<'a, 'b> Add<&'b Scalar> for &'a Share {
    type Output = Share;
    fn add(self, rhs: &'b Scalar) -> Share {
        Share { i: self.i, yi: self.yi + rhs }
    }
}

define_sub_variants!(LHS = Share, RHS = Share, Output = Share);
impl<'a, 'b> Sub<&'b Share> for &'a Share {
    type Output = Share;
    fn sub(self, rhs: &'b Share) -> Share {
        assert!(self.i == rhs.i);
        Share { i: self.i, yi: self.yi - rhs.yi }
    }
}

define_sub_variants!(LHS = Share, RHS = Scalar, Output = Share);
define_sub_variants!(LHS = Scalar, RHS = Share, Output = Share);
define_comut_sub!(LHS = Scalar, RHS = Share, Output = Share);
impl<'a, 'b> Sub<&'b Scalar> for &'a Share {
    type Output = Share;
    fn sub(self, rhs: &'b Scalar) -> Share {
        Share { i: self.i, yi: self.yi - rhs }
    }
}

define_mul_variants!(LHS = Share, RHS = Scalar, Output = Share);
define_mul_variants!(LHS = Scalar, RHS = Share, Output = Share);
define_comut_mul!(LHS = Scalar, RHS = Share, Output = Share);
impl<'a, 'b> Mul<&'b Scalar> for &'a Share {
    type Output = Share;
    fn mul(self, rhs: &'b Scalar) -> Share {
        Share { i: self.i, yi: self.yi * rhs }
    }
}

define_mul_variants!(LHS = Share, RHS = G1Projective, Output = PointShare);
define_mul_variants!(LHS = G1Projective, RHS = Share, Output = PointShare);
define_comut_mul!(LHS = G1Projective, RHS = Share, Output = PointShare);
impl<'a, 'b> Mul<&'b G1Projective> for &'a Share {
    type Output = PointShare;
    fn mul(self, rhs: &'b G1Projective) -> PointShare {
        PointShare { i: self.i, Yi: rhs * self.yi }
    }
}

//-----------------------------------------------------------------------------------------------------------
// PointShare
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug, Copy, Clone)]
pub struct PointShare {
    pub i: u32,
    pub Yi: G1Projective
}

define_add_variants!(LHS = PointShare, RHS = G1Projective, Output = PointShare);
define_add_variants!(LHS = G1Projective, RHS = PointShare, Output = PointShare);
define_comut_add!(LHS = G1Projective, RHS = PointShare, Output = PointShare);
impl<'a, 'b> Add<&'b G1Projective> for &'a PointShare {
    type Output = PointShare;
    fn add(self, rhs: &'b G1Projective) -> PointShare {
        PointShare { i: self.i, Yi: self.Yi + rhs }
    }
}

define_sub_variants!(LHS = PointShare, RHS = G1Projective, Output = PointShare);
define_sub_variants!(LHS = G1Projective, RHS = PointShare, Output = PointShare);
define_comut_sub!(LHS = G1Projective, RHS = PointShare, Output = PointShare);
impl<'a, 'b> Sub<&'b G1Projective> for &'a PointShare {
    type Output = PointShare;
    fn sub(self, rhs: &'b G1Projective) -> PointShare {
        PointShare { i: self.i, Yi: self.Yi - rhs }
    }
}

define_mul_variants!(LHS = PointShare, RHS = Scalar, Output = PointShare);
define_mul_variants!(LHS = Scalar, RHS = PointShare, Output = PointShare);
define_comut_mul!(LHS = Scalar, RHS = PointShare, Output = PointShare);
impl<'a, 'b> Mul<&'b Scalar> for &'a PointShare {
    type Output = PointShare;
    fn mul(self, rhs: &'b Scalar) -> PointShare {
        PointShare { i: self.i, Yi: self.Yi * rhs }
    }
}

//-----------------------------------------------------------------------------------------------------------
// Polynomial
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial(pub Vec<Scalar>);

impl Drop for Polynomial {
    fn drop(&mut self) {
        for item in self.0.iter_mut() {
            item.clear();
        }
    }
}

define_add_variants!(LHS = Polynomial, RHS = Polynomial, Output = Polynomial);
impl<'a, 'b> Add<&'b Polynomial> for &'a Polynomial {
    type Output = Polynomial;
    fn add(self, rhs: &'b Polynomial) -> Polynomial {
        Polynomial(self.0.iter().zip(&rhs.0).map(|(a1, a2)| a1 + a2).collect::<Vec<_>>())
    }
}

define_mul_variants!(LHS = Polynomial, RHS = Scalar, Output = Polynomial);
define_mul_variants!(LHS = Scalar, RHS = Polynomial, Output = Polynomial);
define_comut_mul!(LHS = Scalar, RHS = Polynomial, Output = Polynomial);
impl<'a, 'b> Mul<&'b Scalar> for &'a Polynomial {
    type Output = Polynomial;
    fn mul(self, rhs: &'b Scalar) -> Polynomial {
        Polynomial(self.0.iter().map(|ak| ak * rhs).collect::<Vec<_>>())
    }
}

define_mul_variants!(LHS = Polynomial, RHS = G1Projective, Output = PointPolynomial);
define_mul_variants!(LHS = G1Projective, RHS = Polynomial, Output = PointPolynomial);
define_comut_mul!(LHS = G1Projective, RHS = Polynomial, Output = PointPolynomial);
impl<'a, 'b> Mul<&'b G1Projective> for &'a Polynomial {
    type Output = PointPolynomial;
    fn mul(self, rhs: &'b G1Projective) -> PointPolynomial {
        PointPolynomial(self.0.iter().map(|ak| rhs * ak).collect::<Vec<_>>())
    }
}

impl Polynomial {
    pub fn rnd(secret: Scalar, degree: usize) -> Self {
        let mut coefs = vec![secret];

        let rnd_coefs: Vec<Scalar> = (0..degree).map(|_| rnd_scalar()).collect();
        coefs.extend(rnd_coefs);

        Polynomial(coefs)
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
        let mut rev = self.0.iter().rev();
        let head = *rev.next().unwrap();
            
        rev.fold(head, |partial, coef| partial * x + coef)
    }
}

impl Degree for Polynomial {
    fn degree(&self) -> usize {
        self.0.len() - 1
    }
}

//-----------------------------------------------------------------------------------------------------------
// PointPolynomial
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointPolynomial(pub Vec<G1Projective>);

define_add_variants!(LHS = PointPolynomial, RHS = PointPolynomial, Output = PointPolynomial);
impl<'a, 'b> Add<&'b PointPolynomial> for &'a PointPolynomial {
    type Output = PointPolynomial;
    fn add(self, rhs: &'b PointPolynomial) -> PointPolynomial {
        PointPolynomial(self.0.iter().zip(&rhs.0).map(|(A1, A2)| A1 + A2).collect::<Vec<_>>())
    }
}

define_mul_variants!(LHS = PointPolynomial, RHS = Scalar, Output = PointPolynomial);
define_mul_variants!(LHS = Scalar, RHS = PointPolynomial, Output = PointPolynomial);
define_comut_mul!(LHS = Scalar, RHS = PointPolynomial, Output = PointPolynomial);
impl<'a, 'b> Mul<&'b Scalar> for &'a PointPolynomial {
    type Output = PointPolynomial;
    fn mul(self, rhs: &'b Scalar) -> PointPolynomial {
        PointPolynomial(self.0.iter().map(|Ak| Ak * rhs).collect::<Vec<_>>())
    }
}

impl PointPolynomial {
    pub fn verify(&self, share: &PointShare) -> bool {
        let x = Scalar::from(u64::from(share.i));
        share.Yi == self.evaluate(x)
    }
}

impl Evaluate for PointPolynomial {
    type Output = G1Projective;
    fn evaluate(&self, x: Scalar) -> G1Projective {
        // evaluate using Horner's rule
        let mut rev = self.0.iter().rev();
        let head = *rev.next().unwrap();
            
        rev.fold(head, |partial, coef| partial * x + coef)
    }
}

impl Degree for PointPolynomial {
    fn degree(&self) -> usize {
        self.0.len() - 1
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

define_add_variants!(LHS = ShareVector, RHS = ShareVector, Output = ShareVector);
impl<'a, 'b> Add<&'b ShareVector> for &'a ShareVector {
    type Output = ShareVector;
    fn add(self, rhs: &'b ShareVector) -> ShareVector {
        ShareVector(self.0.iter().zip(&rhs.0).map(|(s1, s2)| {
            if s1.i != s2.i {
                panic!("Shares must be in the same order");
            }

            Share { i: s1.i, yi: s1.yi + s2.yi }
        }).collect::<Vec<_>>())
    }
}

define_add_variants!(LHS = ShareVector, RHS = Scalar, Output = ShareVector);
define_add_variants!(LHS = Scalar, RHS = ShareVector, Output = ShareVector);
define_comut_add!(LHS = Scalar, RHS = ShareVector, Output = ShareVector);
impl<'a, 'b> Add<&'b Scalar> for &'a ShareVector {
    type Output = ShareVector;
    fn add(self, rhs: &'b Scalar) -> ShareVector {
        ShareVector(self.0.iter().map(|s| Share { i: s.i, yi: s.yi + rhs }).collect::<Vec<_>>())
    }
}

define_mul_variants!(LHS = ShareVector, RHS = Scalar, Output = ShareVector);
define_mul_variants!(LHS = Scalar, RHS = ShareVector, Output = ShareVector);
define_comut_mul!(LHS = Scalar, RHS = ShareVector, Output = ShareVector);
impl<'a, 'b> Mul<&'b Scalar> for &'a ShareVector {
    type Output = ShareVector;
    fn mul(self, rhs: &'b Scalar) -> ShareVector {
        ShareVector(self.0.iter().map(|s| Share { i: s.i, yi: s.yi * rhs }).collect::<Vec<_>>())
    }
}

define_mul_variants!(LHS = ShareVector, RHS = G1Projective, Output = PointShareVector);
define_mul_variants!(LHS = G1Projective, RHS = ShareVector, Output = PointShareVector);
define_comut_mul!(LHS = G1Projective, RHS = ShareVector, Output = PointShareVector);
impl<'a, 'b> Mul<&'b G1Projective> for &'a ShareVector {
    type Output = PointShareVector;
    fn mul(self, rhs: &'b G1Projective) -> PointShareVector {
        PointShareVector(self.0.iter().map(|s| PointShare { i: s.i, Yi: rhs * s.yi }).collect::<Vec<_>>())
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

define_add_variants!(LHS = PointShareVector, RHS = PointShareVector, Output = PointShareVector);
impl<'a, 'b> Add<&'b PointShareVector> for &'a PointShareVector {
    type Output = PointShareVector;
    fn add(self, rhs: &'b PointShareVector) -> PointShareVector {
        PointShareVector(self.0.iter().zip(&rhs.0).map(|(s1, s2)| {
            if s1.i != s2.i {
                panic!("Shares must be in the same order");
            }

            PointShare { i: s1.i, Yi: s1.Yi + s2.Yi }
        }).collect::<Vec<_>>())
    }
}

define_add_variants!(LHS = PointShareVector, RHS = G1Projective, Output = PointShareVector);
define_add_variants!(LHS = G1Projective, RHS = PointShareVector, Output = PointShareVector);
define_comut_add!(LHS = G1Projective, RHS = PointShareVector, Output = PointShareVector);
impl<'a, 'b> Add<&'b G1Projective> for &'a PointShareVector {
    type Output = PointShareVector;
    fn add(self, rhs: &'b G1Projective) -> PointShareVector {
        PointShareVector(self.0.iter().map(|s| PointShare { i: s.i, Yi: s.Yi + rhs }).collect::<Vec<_>>())
    }
}

define_mul_variants!(LHS = PointShareVector, RHS = Scalar, Output = PointShareVector);
define_mul_variants!(LHS = Scalar, RHS = PointShareVector, Output = PointShareVector);
define_comut_mul!(LHS = Scalar, RHS = PointShareVector, Output = PointShareVector);
impl<'a, 'b> Mul<&'b Scalar> for &'a PointShareVector {
    type Output = PointShareVector;
    fn mul(self, rhs: &'b Scalar) -> PointShareVector {
        PointShareVector(self.0.iter().map(|s| PointShare { i: s.i, Yi: s.Yi * rhs }).collect::<Vec<_>>())
    }
}

impl Interpolate for PointShareVector {
    type Output = G1Projective;

    fn interpolate(&self) -> G1Projective {
        let range = self.0.iter().map(|s| Scalar::from(s.i as u64)).collect::<Vec<_>>();

        let mut acc = G1Projective::identity();
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

        let mut acc = vec![G1Projective::identity(); range.len()];
        for (i, item) in self.0.iter().enumerate() {
            let (num, barycentric) = lx_num_bar(&range, i);
            for j in 0..num.len() {
                acc[j] += item.Yi * (num[j] * barycentric);
            }
        }

        cut_tail(&mut acc, G1Projective::identity());
        PointPolynomial(acc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rnd_scalar;

    #[test]
    fn interpolation() {
        let G1 = G1Projective::generator();

        let threshold = 3;
        let parties = threshold + 1;

        let s = rnd_scalar();
        let S = G1 * s;

        let poly = Polynomial::rnd(s, threshold);

        let shares = poly.shares(parties);
        let s_res = shares.interpolate();
        assert!(s == s_res);

        let S_poly = poly * G1;
        let S_shares = shares * G1;
        
        for S_sh in S_shares.0.iter() {
            assert!(S_poly.verify(S_sh) == true);
        }

        let S_res = S_shares.interpolate();
        assert!(S == S_res);
    }
}