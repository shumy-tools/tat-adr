use std::collections::HashMap;
use std::time::{Instant, Duration};

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
        let PI_comp = PI.to_compressed();

        let data = &[Tk_comp.as_ref(), PI_comp.as_ref()];
        let sig = ExtSignature::sign(&k, &M, data);

        Token { Tk, M, PI, sig }
    }

    pub fn verify(&self, setup: &NetworkSetup) -> bool {
        let Tk_comp = self.Tk.to_compressed();
        let Mk_comp = self.sig.P1.to_compressed();
        let M_comp = self.M.to_compressed();
        let PI_comp = self.PI.to_compressed();
    
        // verification of Schnorr's signature
        let data = &[Tk_comp.as_ref(), PI_comp.as_ref()];
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
    pub Yl: G1Projective,
    pub Yl_comp: [u8; 48]
}

#[derive(Clone)]
pub struct Profile {
    pub loc: String,
    pub R: G1Projective,
    pub Ar: G1Projective,
    pub Ar_comp: [u8; 48]
}

pub struct NetworkSetup {
    pub threshold: usize,

    pub G1: G1Projective,
    pub G2A: G2Affine,
    
    pub Y: G1Projective,
    pub A1: G1Projective,
    pub A2: G2Projective,
    pub A2A: G2Affine,
    pub A2P: G2Prepared,

    pub Y_comp: [u8; 48],
    pub yi: ShareVector,
    pub ai: ShareVector,

    last: usize,
    sessions: HashMap<String, Session>,
    profiles: HashMap<String, Profile>,
    locations: HashMap<String, Location>
}

impl NetworkSetup {
    // NOTE: simulates a network of "threshold + 1" nodes
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

        Self {
            threshold,
            G1, G2A,
            Y, A1, A2, A2A, A2P,
            Y_comp, yi, ai,
            last: 0,
            sessions: HashMap::new(), profiles: HashMap::new(), locations: HashMap::new()
        }
    }

    // NOTE: simulates insertion of a location
    pub fn location(&mut self, name: &str, Yl: G1Projective) {
        let Yl_comp = G1Affine::from(Yl).to_compressed();
        self.locations.insert(name.into(), Location { Yl, Yl_comp });
    }

    // NOTE: simulates insertion of a profile
    pub fn profile(&mut self, name: &str, loc: &str, R: G1Projective, Ar: G1Projective) {
        if !self.locations.contains_key(loc) {
            panic!("Location doesn't exist!");
        }

        // NOTE: (Ar, R) input validation
        if pairing(&Ar.into(), &self.G2A) != pairing(&R.into(), &self.A2A) {
            panic!("Ar not valid!");
        }

        let Ar_comp = G1Affine::from(Ar).to_compressed();
        self.profiles.insert(name.into(), Profile { loc: loc.into(), R, Ar, Ar_comp });
    }

    // NOTE: start-session returns (Mi, PIi) shares for reconstruction
    pub fn start(&mut self, sig: ExtSignature, profile: &str, seq: usize, time: Instant) -> (PointShareVector, PointShareVector) {
        //NOTE: verification of client signature
        let seq_bytes = seq.to_le_bytes();
        let time_str = format!("{:?}", time);
        let data = &[profile.as_bytes(), seq_bytes.as_ref(), time_str.as_bytes()];
        if !sig.verify(&self.G1.into(), data) {
            panic!("Invalid inputs!");
        }

        //NOTE: verification of client identity and authorizations should be here. However, these stats are not included in the measurements.
        
        let wall = Duration::from_secs(30);
        let now = Instant::now();

        // NOTE: "seq" and "time" in the correct ranges?
        if time < now - wall || time > now + wall || seq <= self.last {
            panic!("Invalid inputs!");
        }
        
        let session = format!("{}-{:?}", seq, time);
        let profile = self.profiles.get(profile).expect("Profile doesn't exist!");
        let location = self.locations.get(&profile.loc).expect("Location doesn't exist!");

        // NOTE: mi shares may be re-calculated or stored in the session (stateless vs stateful)
        let mi = self.mi_shares(&session, location.Yl_comp.as_ref(), profile.Ar_comp.as_ref());

        let res = (&mi * self.G1, &self.yi * profile.R);
        self.last += 1;
        self.sessions.insert(session.into(), Session { mi, profile: profile.clone() });
        
        res
    }

    // NOTE: request-token returns Tki shares for reconstruction
    pub fn request(&mut self, session: &str, Akc: &G1Affine, Kc: &G1Affine) -> PointShareVector {
        // NOTE: (Akc, Kc) input validation
        if pairing(Akc, &self.G2A) != pairing(Kc, &self.A2A) {
            panic!("Akc not valid!");
        }

        let session = self.sessions.remove(session.into()).unwrap();

        // NOTE: all inputs are validated (yi, mi, Ar, Akc)
        &self.yi * session.profile.Ar + &session.mi * G1Projective::from(Akc)
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