use std::collections::HashMap;

use crate::crypto::*;
use bls12_381::{pairing, Scalar, G1Affine, G1Projective, G2Affine, G2Projective, G2Prepared};

//-----------------------------------------------------------------------------------------------------------
// Token
//-----------------------------------------------------------------------------------------------------------
pub struct Token {
    pub Tk: G1Affine,
    pub M: G1Affine,
    pub PI: G1Affine,
    pub sig: ExtSignature
}

impl Token {
    pub fn new(k: Scalar, Tk: G1Affine, M: G1Affine, PI: G1Affine) -> Self {
        let Tk_comp = Tk.to_compressed();
        let M_comp = M.to_compressed();
        let PI_comp = PI.to_compressed();

        let data = &[Tk_comp.as_ref(), M_comp.as_ref(), PI_comp.as_ref()];
        let sig = ExtSignature::sign(&k, &M, data);

        Token { Tk, M, PI, sig }
    }

    pub fn verify(&self, setup: &NetworkSetup) -> bool {
        let Tk_comp = self.Tk.to_compressed();
        let Mk_comp = self.sig.P1.to_compressed();
        let M_comp = self.M.to_compressed();
        let PI_comp = self.PI.to_compressed();
    
        // verification of Schnorr's signature
        let data = &[Tk_comp.as_ref(), M_comp.as_ref(), PI_comp.as_ref()];
        if !self.sig.verify(&self.M, data) {
            return false
        }
    
        // verification of pairing signature
        let c = hash(&[&M_comp, &Mk_comp, &PI_comp]);
        pairing(&self.Tk, &setup.G2A) == multi_pairing(&[self.PI, (self.sig.P1 * c).into()], &setup.A2P)
    }
}

//-----------------------------------------------------------------------------------------------------------
// Simulation of a (t,n)-network
//-----------------------------------------------------------------------------------------------------------
struct Session {
    pub mi: ShareVector,
    pub profile: Profile
}

#[derive(Clone)]
pub struct Location {
    l: Scalar,
    pub Yl: G1Projective,
    pub Yl_comp: [u8; 48]
}

#[derive(Clone)]
pub struct Profile {
    r: Scalar,
    pub loc: String,
    pub R: G1Projective,
    pub Ar: G1Projective,
    pub Ar_comp: [u8; 48]
}

pub struct NetworkSetup {
    pub G1: G1Projective,
    pub G2A: G2Affine,

    pub threshold: usize,
    
    pub Y: G1Projective,
    pub A1: G1Projective,
    pub A2: G2Projective,
    pub A2A: G2Affine,
    pub A2P: G2Prepared,

    pub Y_comp: [u8; 48],
    pub yi: ShareVector,
    pub ai: ShareVector,

    sessions: HashMap<String, Session>,
    profiles: HashMap<String, Profile>,
    locations: HashMap<String, Location>
}

impl NetworkSetup {
    pub fn new(threshold: usize) -> Self {
        let G1: G1Projective = G1Projective::generator();
        let G2A: G2Affine = G2Affine::generator();

        let y = rnd_scalar();
        let a = rnd_scalar();
        
        let Y = G1 * y;
        let A1 = G1 * a;
        let A2 = G2A * a;
        let A2A = G2Affine::from(A2);
        let A2P: G2Prepared = A2A.into();
    
        let y_poly = Polynomial::rnd(y, threshold);
        let a_poly = Polynomial::rnd(a, threshold);
        
        let Y_comp = G1Affine::from(Y).to_compressed();
        let yi = y_poly.shares(threshold + 1);
        let ai = a_poly.shares(threshold + 1);

        Self { G1, G2A, threshold, Y, A1, A2, A2A, A2P, Y_comp, yi, ai, sessions: HashMap::new(), profiles: HashMap::new(), locations: HashMap::new() }
    }

    pub fn location(&mut self, name: &str) {
        let l = rnd_scalar();
        let Yl = self.Y * l;
        let Yl_comp = G1Affine::from(Yl).to_compressed();

        self.locations.insert(name.into(), Location { l, Yl, Yl_comp });
    }

    pub fn profile(&mut self, name: &str, loc: &str) {
        if !self.locations.contains_key(loc) {
            panic!("Location doesn't exist!");
        }

        let r = rnd_scalar();
        let R = self.G1 * r;
        let Ar = self.A1 * r;
        let Ar_comp = G1Affine::from(Ar).to_compressed();

        self.profiles.insert(name.into(), Profile { r, loc: loc.into(), R, Ar, Ar_comp });
    }

    pub fn start(&mut self, session: &str, profile: &str) -> (PointShareVector, PointShareVector) {
        let profile = self.profiles.get(profile).expect("Profile doesn't exist!");
        let location = self.locations.get(&profile.loc).expect("Location doesn't exist!");

        let mi = self.mi_shares(session, location.Yl_comp.as_ref(), profile.Ar_comp.as_ref());

        let res = (&mi * self.G1, &self.yi * profile.R);
        self.sessions.insert(session.into(), Session { mi, profile: profile.clone() });
        
        res
    }

    pub fn request(&self, session: &str, Akc: &G1Affine, Kc: &G1Affine) -> PointShareVector {
        if pairing(Akc, &self.G2A) != pairing(Kc, &self.A2A) {
            panic!("Akc not valid!");
        }

        let AkcP: G1Projective = Akc.into();
        let session = self.sessions.get(session.into()).unwrap();

        &self.yi * session.profile.Ar + &session.mi * AkcP
    }

    fn mi_shares(&self, session: &str, Yl: &[u8], Ar: &[u8]) -> ShareVector {
        let mut mi = Vec::<Share>::new();
        for i in 1..=self.threshold+1 {
            let ni = rnd_scalar();
            let yi = hash(&[ni.to_bytes().as_ref(), session.as_bytes(), self.Y_comp.as_ref(), Yl, Ar]);
            mi.push(Share { i: i as u32, yi });
        }
    
        ShareVector(mi)
    }
}