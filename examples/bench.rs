//! Times key generation, signing and verification across the tree shapes a
//! signer can choose, and prints a table.
//!
//! Verification is the operation that runs on every node, so it is measured
//! over many iterations rather than once. Signing and key generation are
//! measured once each, being seconds rather than microseconds.

use shrincs::{keygen, params::*, sign, verify, Structure};
use std::time::Instant;

fn once(f: impl FnOnce()) -> f64 {
    let t = Instant::now();
    f();
    t.elapsed().as_secs_f64() * 1e3
}

fn repeated(n: u32, mut f: impl FnMut()) -> f64 {
    let t = Instant::now();
    for _ in 0..n {
        f();
    }
    t.elapsed().as_secs_f64() * 1e3 / n as f64
}

fn main() {
    let seed = [0u8; SEED_SIZE];
    let msg = [0u8; 32];

    println!(
        "{:<16} {:>7} {:>9} {:>11} {:>10} {:>12}",
        "configuration", "budget", "sig bytes", "keygen ms", "sign ms", "verify ms"
    );
    println!("{}", "-".repeat(70));

    let shapes = [
        ("UXMSS d=8", Structure::unbalanced(8)),
        ("UXMSS d=255", Structure::unbalanced(255)),
        ("BXMSS d=5", Structure::balanced(5)),
        ("BXMSS d=8", Structure::balanced(8)),
        ("BXMSS d=10", Structure::balanced(10)),
    ];

    for (name, structure) in shapes {
        let mut key = None;
        let t_keygen = once(|| key = Some(keygen(&seed, structure)));
        let (sk, pk) = key.unwrap();

        // The first leaf, which is the smallest signature a shape produces.
        let mut sig = None;
        let t_sign = once(|| sig = sign(&msg, b"", &sk, Some(0), None));
        let sig = sig.unwrap();
        let t_verify = repeated(200, || assert!(verify(&msg, &sig, b"", &pk)));

        println!(
            "{:<16} {:>7} {:>9} {:>11.0} {:>10.1} {:>12.4}",
            name,
            structure.budget(),
            sig.len(),
            t_keygen,
            t_sign,
            t_verify
        );
    }

    // The fallback is the same whatever shape the stateful side has.
    let (sk, pk) = keygen(&seed, Structure::balanced(5));
    let mut fb = None;
    let t_sign = once(|| fb = sign(&msg, b"", &sk, None, None));
    let fb = fb.unwrap();
    let t_verify = repeated(50, || assert!(verify(&msg, &fb, b"", &pk)));
    println!(
        "{:<16} {:>7} {:>9} {:>11} {:>10.0} {:>12.4}",
        "stateless",
        "2^40",
        fb.len(),
        "-",
        t_sign,
        t_verify
    );

    // The largest stateful signature, at the deepest leaf of the deepest tree.
    let structure = Structure::unbalanced(255);
    let (sk, pk) = keygen(&seed, structure);
    let last = structure.budget() - 1;
    let big = sign(&msg, b"", &sk, Some(last), None).unwrap();
    let t_verify = repeated(200, || assert!(verify(&msg, &big, b"", &pk)));
    println!(
        "{:<16} {:>7} {:>9} {:>11} {:>10} {:>12.4}",
        "  deepest leaf",
        "-",
        big.len(),
        "-",
        "-",
        t_verify
    );
}
