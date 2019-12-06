#![allow(dead_code)]

use sha2::{Sha512, Digest};
use bls12_381::{Scalar, G1Affine};

/*fn pop(barry: &[u8]) -> &[u8; 3] {
    barry.try_into().expect("slice with incorrect length")
}*/

fn hash_c(G1: &G1Affine, P1: &G1Affine, M: &G1Affine, data: &[&[u8]]) -> Scalar {
    let mut hasher = Sha512::new()
        .chain(G1.to_compressed().as_ref())
        .chain(P1.to_compressed().as_ref())
        .chain(M.to_compressed().as_ref());
    
    for d in data {
        hasher.input(d);
    }
    
    let result = unsafe {
        &*(hasher.result().as_ptr() as *const [u8; 64])
    };

    Scalar::from_bytes_wide(result)
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
        let p = m - c * s;

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
    pub fn sign(s: &Scalar, G1: &G1Affine, P1: G1Affine, data: &[&[u8]]) -> Self {
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
        let Ps: G1Affine = (G1 * s).into();

        let d0 = rnd_scalar().to_bytes();
        let d1 = rnd_scalar().to_bytes();

        let data = &[d0.as_ref(), d1.as_ref()];
        let sig = ExtSignature::sign(&s, &G1, Ps, data);
        
        assert!(sig.verify(&G1, data) == true);
    }

    #[test]
    fn incorrect() {
        let G1 = G1Affine::generator();

        let s = rnd_scalar();
        let Ps: G1Affine = (G1 * s).into();

        let d0 = rnd_scalar().to_bytes();
        let d1 = rnd_scalar().to_bytes();
        let d2 = rnd_scalar().to_bytes();
        
        let data1 = &[d0.as_ref(), d1.as_ref()];
        let sig = ExtSignature::sign(&s, &G1, Ps, data1);
        
        let data2 = &[d0.as_ref(), d2.as_ref()];
        assert!(sig.verify(&G1, data2) == false);
    }
}