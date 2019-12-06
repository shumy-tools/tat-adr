#![allow(non_snake_case)]

mod tatadr;
mod crypto;

use crate::tatadr::*;
use crate::crypto::*;

use rand::prelude::*;

use clap::{Arg, App};
use std::time::{Instant, Duration};
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
        .arg(Arg::with_name("runs")
            .help("Sets the number of runs.")
            .required(true)
            .short("r")
            .long("runs")
            .takes_value(true))
        .get_matches();

    // setup parameters
    let str_threshold = matches.value_of("threshold").unwrap();
    let threshold = str_threshold.parse::<usize>().unwrap();

    let str_runs = matches.value_of("runs").unwrap();
    let runs = str_runs.parse::<usize>().unwrap();

    println!("Setup: (threshold: {}, runs: {})", threshold, runs);

    // setup private keys
    let l = rnd_scalar(); // location key
    let r = rnd_scalar(); // profile key
    let k = rnd_scalar(); // client-token key

    // setup network
    let mut setup = NetworkSetup::new(threshold);
    setup.location("Hospital", setup.Y * l);
    setup.profile("EHR", "Hospital", setup.G1 * r, setup.A1 * r);

    // collect stats for runs
    let mut round1 = Duration::from_millis(0);
    let mut round2 = Duration::from_millis(0);
    let mut round3 = Duration::from_millis(0);
    let mut total = Duration::from_millis(0);

    let mut rng = rand::thread_rng();
    for _ in 0..runs {
        let rnd: f64 = rng.gen();
        let session = format!("rand-session-{}", rnd);

        let init = Instant::now();

            // start session (round 1)
            let (Mi, PIi) = setup.start(&session, "EHR");

            let M = Mi.interpolate();
            let Mk = M * k;
            let PI = PIi.interpolate();

            let M_comp = G1Affine::from(M).to_compressed();
            let Mk_comp = G1Affine::from(Mk).to_compressed();
            let PI_comp = G1Affine::from(PI).to_compressed();

            let c = hash(&[&M_comp, &Mk_comp, &PI_comp]);
            let Kc = setup.G1 * (k * c);
            let Akc = setup.A1 * (k * c);
            let round1_i = Instant::now() - init;

            // request token (round 2)
            let Tki = setup.request(&session, &Akc.into(), &Kc.into());

            let Tk = Tki.interpolate();
            let token = Token::new(k, Tk.into(), M.into(), PI.into());
            let round2_i = (Instant::now() - init) - round1_i;

            // verify token (round 3)
            assert!(token.verify(&setup));
            let round3_i = (Instant::now() - init) - round1_i - round2_i;

        let total_i = Instant::now() - init;

        round1 += round1_i;
        round2 += round2_i;
        round3 += round3_i;
        total += total_i;
    }

    println!("Stats: (start: {:?}ms, request: {:?}ms, verify: {:?}ms, total/sum: {:?}ms == {:?}ms)",
    (round1/runs as u32).as_micros() as f64/1000.0,
    (round2/runs as u32).as_micros() as f64/1000.0,
    (round3/runs as u32).as_micros() as f64/1000.0,
    (total/runs as u32).as_micros() as f64/1000.0, ((round1 + round2 + round3)/runs as u32).as_micros() as f64/1000.0);
}
