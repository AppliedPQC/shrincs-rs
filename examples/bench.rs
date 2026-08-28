//! Times the four operations the C++ implementation's benchmark times, so the
//! two can be read side by side on one machine.
//!
//! The two are not the same scheme. `BlockstreamResearch/shrincs-cpp` predates
//! this draft and builds on w = 256 over 16 chains with PORS+FP, where the
//! draft specifies w = 16 over 32 chains with FORS. Sizes are printed beside
//! the timings so the difference is visible rather than implied.

use shrincs::{keygen, params::*, sign, verify, Structure};
use std::time::Instant;

fn ms(f: impl FnOnce()) -> f64 {
    let t = Instant::now();
    f();
    t.elapsed().as_secs_f64() * 1e3
}

fn main() {
    let seed = [0u8; SEED_SIZE];
    let message = [0u8; 32];

    for structure in [Structure::unbalanced(255), Structure::balanced(8)] {
        let label = if structure.0[0] == FXMSS_SHAPE_UNBALANCED {
            "UXMSS"
        } else {
            "BXMSS"
        };
        println!(
            "\n== {label} depth {} ==  budget {}",
            structure.depth(),
            structure.budget()
        );

        let mut key = None;
        let t_keygen = ms(|| key = Some(keygen(&seed, structure)));
        let (sk, pk) = key.unwrap();
        println!("  key generation        {t_keygen:9.2} ms");

        let mut sig = None;
        let t_sign = ms(|| sig = sign(&message, b"", &sk, Some(0), None));
        let sig = sig.unwrap();
        let t_verify = ms(|| assert!(verify(&message, &sig, b"", &pk)));
        println!(
            "  stateful signing      {t_sign:9.2} ms     {} bytes",
            sig.len()
        );
        println!("  stateful verification {t_verify:9.4} ms");

        let mut fb = None;
        let t_fsign = ms(|| fb = sign(&message, b"", &sk, None, None));
        let fb = fb.unwrap();
        let t_fverify = ms(|| assert!(verify(&message, &fb, b"", &pk)));
        println!(
            "  stateless signing     {t_fsign:9.2} ms     {} bytes",
            fb.len()
        );
        println!("  stateless verification{t_fverify:9.4} ms");
    }
}
