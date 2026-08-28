//! Cross-check against NIST's own SLH-DSA vectors.
//!
//! SHRINCS's stateless component is FIPS 205 under a non-standard parameter
//! set. That claim is only worth something if the shared machinery really is
//! FIPS 205, so the same code is instantiated here at the *standard* sets and
//! run against NIST's ACVP vectors — the inputs and expected outputs NIST
//! publishes for validating implementations.
//!
//! For the category-1 SHA2 sets the constructions coincide exactly: `F`, `H`,
//! `T` and `PRF` are all `SHA256(pk_seed || 0^48 || ADRS_c || .)[..16]`,
//! `PRF_msg` is HMAC-SHA-256 truncated the same way, and `H_msg` is MGF1 over
//! SHA-256. The 22-byte address this crate uses *is* FIPS 205's compressed
//! `ADRS_c`.
//!
//! The vectors are ~37 MB and are not committed. Fetch them with
//! `./fetch-vectors.sh`, or set `ACVP_DIR`. Without them these tests skip.

use serde_json::Value;
use shrincs::{
    adrs::Adrs,
    hash::Sha256,
    params::{SlhParams, SLH_DSA_SHA2_128F, SLH_DSA_SHA2_128S},
    stateless,
};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn vectors(name: &str) -> Option<Value> {
    let dir = std::env::var("ACVP_DIR").unwrap_or_else(|_| "vectors".into());
    let path = format!("{dir}/{name}");
    match std::fs::read_to_string(&path) {
        Ok(t) => Some(serde_json::from_str(&t).expect("vector file is not valid JSON")),
        Err(_) => {
            eprintln!("skipping: {path} not present (run ./fetch-vectors.sh)");
            None
        }
    }
}

fn set_for(name: &str) -> Option<&'static SlhParams> {
    match name {
        "SLH-DSA-SHA2-128s" => Some(&SLH_DSA_SHA2_128S),
        "SLH-DSA-SHA2-128f" => Some(&SLH_DSA_SHA2_128F),
        _ => None, // the other ten sets use SHA-512 or SHAKE, which this crate has no need of
    }
}

#[test]
fn keygen_matches_nist_vectors() {
    let Some(v) = vectors("SLH-DSA-keyGen-FIPS205.json") else {
        return;
    };
    let mut checked = 0;
    for group in v["testGroups"].as_array().unwrap() {
        let Some(p) = set_for(group["parameterSet"].as_str().unwrap_or("")) else {
            continue;
        };
        for t in group["tests"].as_array().unwrap() {
            let sk_seed = hex(t["skSeed"].as_str().unwrap());
            let pk_seed = hex(t["pkSeed"].as_str().unwrap());
            let want = hex(t["pk"].as_str().unwrap());

            let mut adrs = Adrs::new();
            adrs.set_layer((p.d - 1) as u8);
            let root = stateless::xmss_node::<Sha256>(&sk_seed, 0, p.h_prime, &pk_seed, &mut adrs);

            let mut got = pk_seed.clone();
            got.extend_from_slice(&root);
            assert_eq!(got, want, "{} tcId {}", p.name, t["tcId"]);
            checked += 1;
        }
    }
    assert!(
        checked > 0,
        "no category-1 SHA2 groups found in the vector file"
    );
    println!("keyGen: {checked} NIST vectors reproduced");
}

#[test]
fn signatures_match_nist_vectors() {
    let Some(v) = vectors("SLH-DSA-sigGen-FIPS205.json") else {
        return;
    };
    let mut signed = 0;
    for group in v["testGroups"].as_array().unwrap() {
        let Some(p) = set_for(group["parameterSet"].as_str().unwrap_or("")) else {
            continue;
        };
        // Only the plain, non-prehashed, internal-interface groups are the ones
        // this crate's stateless component corresponds to.
        if group["signatureInterface"].as_str() != Some("internal") {
            continue;
        }
        let deterministic = group["deterministic"].as_bool().unwrap_or(false);
        for t in group["tests"].as_array().unwrap() {
            let sk = hex(t["sk"].as_str().unwrap());
            let (sk_seed, sk_prf, pk_seed, pk_root) =
                (&sk[0..16], &sk[16..32], &sk[32..48], &sk[48..64]);
            let msg = hex(t["message"].as_str().unwrap());
            let want = hex(t["signature"].as_str().unwrap());
            let addrnd = t
                .get("additionalRandomness")
                .and_then(|x| x.as_str())
                .map(hex);
            let opt_rand: Option<&[u8]> = if deterministic {
                Some(pk_seed)
            } else {
                match addrnd.as_deref() {
                    Some(r) => Some(r),
                    None => continue,
                }
            };

            let got = stateless::slh_dsa_sign_internal::<Sha256>(
                &[&msg],
                sk_seed,
                sk_prf,
                pk_seed,
                pk_root,
                opt_rand,
                p,
            );
            assert_eq!(got.len(), p.signature_size(), "{} size", p.name);
            assert_eq!(got, want, "{} tcId {}", p.name, t["tcId"]);
            assert!(
                stateless::slh_dsa_verify_internal::<Sha256>(&[&msg], &got, pk_seed, pk_root, p),
                "own signature must verify"
            );
            signed += 1;
            if signed >= 4 {
                break; // signing at these sets is seconds apiece; four is enough to pin it
            }
        }
    }
    assert!(signed > 0, "no usable groups found");
    println!("sigGen: {signed} NIST vectors reproduced byte for byte");
}

/// NIST's negative-test suite: signatures that must be *rejected*, and why.
///
/// This is the part a hand-rolled tamper test cannot match. NIST curates six
/// distinct failure modes — a modified message, a modified `R`, a modified
/// FORS signature, a modified hypertree signature, and signatures too long and
/// too short — alongside valid cases that must still verify. Getting all of
/// them right means the verifier rejects for the right reasons rather than
/// rejecting everything.
#[test]
fn verification_matches_nist_vectors_including_the_negative_cases() {
    let Some(v) = vectors("SLH-DSA-sigVer-FIPS205.json") else {
        return;
    };
    let mut accepted = 0;
    let mut rejected = 0;
    let mut by_reason: std::collections::BTreeMap<String, usize> = Default::default();

    for group in v["testGroups"].as_array().unwrap() {
        let Some(p) = set_for(group["parameterSet"].as_str().unwrap_or("")) else {
            continue;
        };
        if group["signatureInterface"].as_str() != Some("internal") {
            continue;
        }
        for t in group["tests"].as_array().unwrap() {
            let pk = hex(t["pk"].as_str().unwrap());
            let (pk_seed, pk_root) = (&pk[0..16], &pk[16..32]);
            let msg = hex(t["message"].as_str().unwrap());
            let sig = hex(t["signature"].as_str().unwrap());
            let want = t["testPassed"].as_bool().unwrap();
            let reason = t["reason"].as_str().unwrap_or("?").to_string();

            let got =
                stateless::slh_dsa_verify_internal::<Sha256>(&[&msg], &sig, pk_seed, pk_root, p);
            assert_eq!(got, want, "{} tcId {}: {}", p.name, t["tcId"], reason);

            *by_reason.entry(reason).or_default() += 1;
            if want {
                accepted += 1
            } else {
                rejected += 1
            }
        }
    }
    assert!(
        accepted > 0 && rejected > 0,
        "expected both valid and invalid cases"
    );
    println!("sigVer: {accepted} accepted, {rejected} correctly rejected");
    for (reason, n) in by_reason {
        println!("   {n:3}  {reason}");
    }
}
