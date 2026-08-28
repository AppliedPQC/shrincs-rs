//! A signing and verifying oracle, driven over JSON, so the draft's reference
//! implementation and this crate can be pointed at each other.
//!
//! Byte-equality of signatures tests only the signer. This lets the two verify
//! each other's output, which is the only thing that tests a verifier against
//! an independent implementation.
//!
//!     cargo run --release --example interop -- sign   < jobs.json
//!     cargo run --release --example interop -- verify < jobs.json
//!
//! See `interop.py`, which drives both directions and compares.

use serde_json::{json, Value};
use shrincs::{keygen, sign, verify, PublicKey, SecretKey, Structure};
use std::io::Read;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let mode = std::env::args().nth(1).expect("sign | verify");
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let jobs: Value = serde_json::from_str(&input).unwrap();
    let mut out = Vec::new();

    for job in jobs.as_array().unwrap() {
        let msg = hex(job["msg"].as_str().unwrap());
        let ctx = hex(job["ctx"].as_str().unwrap());
        match mode.as_str() {
            "sign" => {
                let seed: [u8; 48] = hex(job["seed"].as_str().unwrap()).try_into().unwrap();
                let structure = Structure([job["shape"].as_u64().unwrap() as u8,
                                           job["depth"].as_u64().unwrap() as u8]);
                let (sk, pk): (SecretKey, PublicKey) = keygen(&seed, structure);
                let ctr = job["ctr"].as_u64();
                let opt_rand = job.get("opt_rand").and_then(|v| v.as_str()).map(hex);
                let sig = sign(&msg, &ctx, &sk, ctr, opt_rand.as_deref());
                out.push(json!({
                    "pubkey": hx(&pk),
                    "sig": sig.as_ref().map(|s| hx(s)),
                }));
            }
            "verify" => {
                let pk: PublicKey = hex(job["pubkey"].as_str().unwrap()).try_into()
                    .expect("public key must be 48 bytes");
                let sig = hex(job["sig"].as_str().unwrap());
                out.push(json!({ "ok": verify(&msg, &sig, &ctx, &pk) }));
            }
            other => panic!("unknown mode {other}"),
        }
    }
    println!("{}", serde_json::to_string(&out).unwrap());
}
