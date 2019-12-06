#![allow(non_snake_case)]

mod tatadr;
mod crypto;

use crate::tatadr::*;
use crate::crypto::*;

use clap::{Arg, App};
use std::time::Instant;
use bls12_381::G1Affine;

fn main() {
    let matches = App::new("Simulations for TAT-ADR")
        .version("1.0")
        .author("Micael Pedrosa <micaelpedrosa@ua.pt>")
        .about("Simulations and measurements for (Threshold access token for anonymous data resources)")
        .arg(Arg::with_name("threshold")
            .help("Sets the threshold number (t). The number of parties are set automatically to t+1.")
            .required(true)
            .short("t")
            .long("threshold")
            .takes_value(true))
        .get_matches();
    
    //let select = matches.value_of("select").unwrap();

    let str_threshold = matches.value_of("threshold").unwrap();
    let threshold = str_threshold.parse::<usize>().unwrap();
    println!("Setup: (threshold={})", threshold);

    // setup network
    let mut setup = NetworkSetup::new(threshold);
    setup.location("Hospital");
    setup.profile("EHR", "Hospital");

    // setup client
    let session = "rand-session";
    let k = rnd_scalar();

    let start = Instant::now();
        // start session
        let (Mi, PIi) = setup.start(session, "EHR");

        let M = Mi.interpolate();
        let Mk = M * k;
        let PI = PIi.interpolate();

        let M_comp = G1Affine::from(M).to_compressed();
        let Mk_comp = G1Affine::from(Mk).to_compressed();
        let PI_comp = G1Affine::from(PI).to_compressed();

        let c = hash(&[&M_comp, &Mk_comp, &PI_comp]);
        let Kc = setup.G1 * (k * c);
        let Akc = setup.A1 * (k * c);

        // token request
        let Tki = setup.request(session, &Akc.into(), &Kc.into());

        let Tk = Tki.interpolate();
        let token = Token::new(k, Tk.into(), M.into(), PI.into());

        // validate token
        assert!(token.verify(&setup));
    let run = Instant::now() - start;
    println!("RUN: {:?}ms", run.as_millis());
}
