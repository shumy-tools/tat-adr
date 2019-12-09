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
    let mut round1_1 = Duration::from_millis(0);
    let mut round1_2 = Duration::from_millis(0);
    let mut round2_1 = Duration::from_millis(0);
    let mut round2_2 = Duration::from_millis(0);
    let mut round3 = Duration::from_millis(0);

    let mut rng = rand::thread_rng();
    for _ in 0..runs {
        let rnd: f64 = rng.gen();
        let session = format!("rand-session-{}", rnd);

        let init = Instant::now();

            // start session (round 1)
                let (Mi, PIi) = setup.start(&session, "EHR");
            let round1_1_i = Instant::now() - init;

                let M = Mi.interpolate();
                let Mk = M * k;
                let PI = PIi.interpolate();

                let M_comp = G1Affine::from(M).to_compressed();
                let Mk_comp = G1Affine::from(Mk).to_compressed();
                let PI_comp = G1Affine::from(PI).to_compressed();

                let c = hash(&[&M_comp, &Mk_comp, &PI_comp]);
                let Kc = setup.G1 * (k * c);
                let Akc = setup.A1 * (k * c);
            let round1_2_i = (Instant::now() - init) - round1_1_i;

            // request token (round 2)
                let Tki = setup.request(&session, &Akc.into(), &Kc.into());
            let round2_1_i = (Instant::now() - init) - round1_1_i - round1_2_i;

                let Tk = Tki.interpolate();
                let token = Token::new(k, Tk.into(), M.into(), PI.into());
            let round2_2_i = (Instant::now() - init) - round1_1_i - round1_2_i - round2_1_i;

            // verify token (round 3)
                assert!(token.verify(&setup));
            let round3_i = (Instant::now() - init) - round1_1_i - round1_2_i - round2_1_i - round2_2_i;

        round1_1 += round1_1_i;
        round1_2 += round1_2_i;
        round2_1 += round2_1_i;
        round2_2 += round2_2_i;
        round3 += round3_i;
    }

    // NOTE: "start" and "request" are simulated in a single thread, but in reality this is a parallel task. It must be divided by (t + 1)
    let stat1_1 = (round1_1/runs as u32).as_micros() as f64/(1000.0 * (threshold + 1) as f64);
    let stat1_2 = (round1_2/runs as u32).as_micros() as f64/1000.0;
    let stat2_1 = (round2_1/runs as u32).as_micros() as f64/(1000.0 * (threshold + 1) as f64);
    let stat2_2 = (round2_2/runs as u32).as_micros() as f64/1000.0;
    let stat3 = (round3/runs as u32).as_micros() as f64/1000.0;
    let stat_total = stat1_1 + stat1_2 + stat2_1 + stat2_2 + stat3;


    println!("Stats: (start-net: {:.3}ms, start-cli: {:.3}ms, request-net: {:.3}ms, request-cli: {:.3}ms, verify: {:.3}ms, total: {:.3}ms)",
        stat1_1, stat1_2, stat2_1, stat2_2, stat3, stat_total);
}
