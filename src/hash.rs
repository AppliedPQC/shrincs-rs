//! The hash family, all built from SHA-256.
//!
//! Every tweakable hash has the same shape:
//!
//! ```text
//! sha256(pk_seed || 0^48 || ADRS || M)[..16]
//! ```
//!
//! The 48 zero bytes bring `pk_seed` up to 64, one full SHA-256 block, so an
//! implementation can compress that block once and reuse the state. `H_GRIND`
//! is the one exception: it reads only the first ten ADRS bytes so that its
//! whole input fits a single further compression, which matters because
//! grinding runs up to 2^16 times per signature.

use crate::adrs::Adrs;
use crate::params::N;
use sha2::{Digest, Sha256};

pub type Hash = [u8; N];

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn truncate(d: [u8; 32]) -> Hash {
    let mut out = [0u8; N];
    out.copy_from_slice(&d[..N]);
    out
}

const PAD48: [u8; 48] = [0u8; 48];

/// The common tweakable hash. `F`, `H`, `T_sl`, `T_sf` and `T_k` of the draft
/// are all this function; they differ only in the ADRS handed to them, which
/// is the point of an address.
pub fn t(pk_seed: &[u8], adrs: &Adrs, m: &[&[u8]]) -> Hash {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(3 + m.len());
    parts.push(pk_seed);
    parts.push(&PAD48);
    parts.push(adrs.as_bytes());
    parts.extend_from_slice(m);
    truncate(sha256(&parts))
}

/// One step of a Winternitz chain, or one Merkle parent: same function, and
/// only the address distinguishes them.
pub fn f(pk_seed: &[u8], adrs: &Adrs, m: &[u8]) -> Hash {
    t(pk_seed, adrs, &[m])
}

/// Combines two Merkle children.
pub fn h(pk_seed: &[u8], adrs: &Adrs, left: &[u8], right: &[u8]) -> Hash {
    t(pk_seed, adrs, &[left, right])
}

/// Reads only `ADRS[..10]`, so the whole input fits one compression.
pub fn h_grind(pk_seed: &[u8], adrs: &Adrs, digest: &[u8], counter: u16) -> Hash {
    truncate(sha256(&[
        pk_seed,
        &PAD48,
        &adrs.as_bytes()[..10],
        digest,
        &[0u8; 4],
        &counter.to_be_bytes(),
    ]))
}

/// Derives a chain or FORS secret. Consumes the whole 22-byte address, which
/// is how an FXMSS tree shape reaches every secret it owns.
pub fn prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs) -> Hash {
    truncate(sha256(&[pk_seed, &PAD48, adrs.as_bytes(), sk_seed]))
}

fn hmac_sha256(key: &[u8], message: &[&[u8]]) -> [u8; 32] {
    debug_assert!(key.len() <= 64);
    let mut padded = [0u8; 64];
    padded[..key.len()].copy_from_slice(key);
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= padded[i];
        opad[i] ^= padded[i];
    }
    let mut inner_parts: Vec<&[u8]> = Vec::with_capacity(1 + message.len());
    inner_parts.push(&ipad);
    inner_parts.extend_from_slice(message);
    let inner = sha256(&inner_parts);
    sha256(&[&opad, &inner])
}

/// Message randomiser for the stateless path.
pub fn prf_msg_sl(sk_prf: &[u8], opt_rand: &[u8], m: &[&[u8]]) -> Hash {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(1 + m.len());
    parts.push(opt_rand);
    parts.extend_from_slice(m);
    truncate(hmac_sha256(sk_prf, &parts))
}

/// Message randomiser for the stateful path. The key is padded with 0xFF so
/// that it cannot coincide with the stateless key above.
pub fn prf_msg_sf(sk_prf: &[u8], pk_seed: &[u8], adrs: &Adrs, m: &[&[u8]]) -> Hash {
    let mut key = [0xFFu8; 64];
    key[..sk_prf.len()].copy_from_slice(sk_prf);
    let mut parts: Vec<&[u8]> = Vec::with_capacity(2 + m.len());
    parts.push(pk_seed);
    parts.push(&adrs.as_bytes()[..9]);
    parts.extend_from_slice(m);
    truncate(hmac_sha256(&key, &parts))
}

/// Stateless message digest. Takes its own root as a parameter; the caller
/// passes the stateful root inside `m`, which is the cross-binding.
pub fn h_msg_sl(r: &[u8], pk_seed: &[u8], sl_root: &[u8], m: &[&[u8]]) -> [u8; 32] {
    let mut inner_parts: Vec<&[u8]> = vec![r, pk_seed, sl_root];
    inner_parts.extend_from_slice(m);
    let inner = sha256(&inner_parts);
    sha256(&[r, pk_seed, &inner, &[0u8; 4]])
}

/// Stateful message digest, binding the leaf position through `ADRS[..9]`.
pub fn h_msg_sf(r: &[u8], pk_seed: &[u8], sf_root: &[u8], adrs: &Adrs, m: &[&[u8]]) -> [u8; 32] {
    let a9 = &adrs.as_bytes()[..9];
    let mut inner_parts: Vec<&[u8]> = vec![r, pk_seed, sf_root, a9];
    inner_parts.extend_from_slice(m);
    let inner = sha256(&inner_parts);
    sha256(&[r, pk_seed, &inner, a9])
}

/// Reads `out_len` big-endian fields of `b` bits each from `x`.
pub fn base_2b(x: &[u8], b: usize, out_len: usize) -> Vec<u32> {
    debug_assert!(x.len() >= (out_len * b).div_ceil(8));
    let mut out = Vec::with_capacity(out_len);
    let (mut j, mut acc, mut bits) = (0usize, 0u64, 0usize);
    for _ in 0..out_len {
        while bits < b {
            acc = (acc << 8) | x[j] as u64;
            j += 1;
            bits += 8;
        }
        bits -= b;
        out.push(((acc >> bits) & ((1u64 << b) - 1)) as u32);
    }
    out
}
