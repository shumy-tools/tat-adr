#![allow(dead_code)]

use sha2::{Sha512, Digest};
use bls12_381::{Scalar, G1Affine};

pub fn hash(data: &[&[u8]]) -> Scalar {
    let mut hasher = Sha512::new();
    for d in data {
        hasher.input(*d);
    }
    
    let result = unsafe {
        &*(hasher.result().as_ptr() as *const [u8; 64])
    };

    Scalar::from_bytes_wide(result)
}

fn hash_c(G1: &G1Affine, P1: &G1Affine, M: &G1Affine, data: &[&[u8]]) -> Scalar {
    let G1_comp = G1.to_compressed();
    let P1_comp = P1.to_compressed();
    let M_comp = M.to_compressed();

    let mut all = vec![G1_comp.as_ref(), P1_comp.as_ref(), M_comp.as_ref()];
    all.extend_from_slice(data);
    hash(&all)
}

//-----------------------------------------------------------------------------------------------------------
// Schnorr's signature
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct Signature {
    pub c: Scalar,
    pub p: Scalar
}

impl Signature {
    pub fn sign(s: &Scalar, G1: &G1Affine, P1: &G1Affine, data: &[&[u8]]) -> Self {
        let mut hasher = Sha512::new()
            .chain(s.to_bytes());
        
        for d in data {
            hasher.input(d);
        }

        let mut result = [0u8; 64];
        result.copy_from_slice(&hasher.result()[0..64]);

        let m = Scalar::from_bytes_wide(&result);
        let M: G1Affine = (G1 * m).into();

        let c = hash_c(G1, P1, &M, data);

        Self { c, p: m - c * s }
    }

    pub fn verify(&self, G1: &G1Affine, P1: &G1Affine, data: &[&[u8]]) -> bool {
        let M: G1Affine = (P1 * self.c + G1 * self.p).into();

        let c = hash_c(G1, P1, &M, data);
        c == self.c
    }
}

//-----------------------------------------------------------------------------------------------------------
// Schnorr's signature with PublicKey (Extended Signature)
//-----------------------------------------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct ExtSignature {
    pub P1: G1Affine,
    pub sig: Signature
}

impl ExtSignature {
    pub fn sign(s: &Scalar, G1: &G1Affine, data: &[&[u8]]) -> Self {
        let P1 = (G1 * s).into();
        let sig = Signature::sign(s, G1, &P1, data);
        Self { P1, sig }
    }

    pub fn verify(&self, G1: &G1Affine, data: &[&[u8]]) -> bool {
        self.sig.verify(G1, &self.P1, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rnd_scalar;

    #[test]
    fn correct() {
        let G1 = G1Affine::generator();

        let s = rnd_scalar();

        let d0 = rnd_scalar().to_bytes();
        let d1 = rnd_scalar().to_bytes();

        let data = &[d0.as_ref(), d1.as_ref()];
        let sig = ExtSignature::sign(&s, &G1, data);
        
        assert!(sig.verify(&G1, data) == true);
    }

    #[test]
    fn incorrect() {
        let G1 = G1Affine::generator();

        let s = rnd_scalar();

        let d0 = rnd_scalar().to_bytes();
        let d1 = rnd_scalar().to_bytes();
        let d2 = rnd_scalar().to_bytes();
        
        let data1 = &[d0.as_ref(), d1.as_ref()];
        let sig = ExtSignature::sign(&s, &G1, data1);
        
        let data2 = &[d0.as_ref(), d2.as_ref()];
        assert!(sig.verify(&G1, data2) == false);
    }
}