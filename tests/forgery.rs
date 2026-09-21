//! Reproduces the SHRINCS one-time-key-reuse forgery (issue #59) against this
//! crate's verifier, from a frozen fixture.
//!
//! The fixture `attack-59/forged-job.json` is a signature on a message that was
//! never signed, forged from only the public key and four honest signatures that
//! a cache rollback made reuse one FXMSS leaf (see `attack-59/forge.py`, which
//! also proves the upstream reference verifier accepts the same bytes). This
//! test shows `verify` here accepts the identical bytes, so the scheme-level
//! break reaches every conforming implementation, not one codebase. The control
//! fixture is the same forgery with one flipped bit and must be rejected, so the
//! acceptance is not vacuous.
//!
//! Ignored by default: it asserts a forgery verifies, which documents the defect
//! rather than a desirable invariant. Run with:
//!     cargo test --test forgery -- --ignored --nocapture

use shrincs::{verify, PublicKey};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn load(path: &str) -> (Vec<u8>, Vec<u8>, PublicKey, Vec<u8>) {
    let text = std::fs::read_to_string(path).expect("fixture present");
    parse(&text)
}

fn parse(text: &str) -> (Vec<u8>, Vec<u8>, PublicKey, Vec<u8>) {
    let job = &serde_json::from_str::<serde_json::Value>(text).unwrap()[0];
    let f = |k: &str| hex(job[k].as_str().unwrap());
    let pk: PublicKey = f("pubkey").try_into().expect("48-byte key");
    (f("msg"), f("ctx"), pk, f("sig"))
}

#[test]
#[ignore = "documents the #59 forgery: asserts a forged signature verifies"]
fn forged_signature_is_accepted() {
    // Fixtures are generated, not committed. Run `attack-59/forge.py` (or
    // `attack-59/reproduce.sh`) first; skip cleanly if they are absent.
    if !std::path::Path::new("attack-59/forged-job.json").exists() {
        eprintln!("skipped: run attack-59/forge.py to generate the fixtures first");
        return;
    }
    let (msg, ctx, pk, sig) = load("attack-59/forged-job.json");
    assert!(
        verify(&msg, &sig, &ctx, &pk),
        "forged signature on a never-signed message must verify, reproducing #59"
    );
    // Control 1: the forgery under a different message must be rejected.
    assert!(
        !verify(b"a different never-signed message", &sig, &ctx, &pk),
        "the forgery must not verify under a different message"
    );
    // Control 2: a one-bit tamper of the forgery must be rejected.
    let (cmsg, cctx, cpk, csig) = load("attack-59/control-job.json");
    assert!(
        !verify(&cmsg, &csig, &cctx, &cpk),
        "a one-bit-tampered forgery must be rejected"
    );
}
