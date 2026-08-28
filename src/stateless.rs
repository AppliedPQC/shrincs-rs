//! The stateless fallback: SLH-DSA under a non-standard parameter set.
//!
//! This is FIPS 205 unmodified apart from the parameters and the caller
//! supplying the randomiser, which is the point: the fallback inherits the
//! standard's analysis rather than asking for a new one.

use crate::adrs::*;
use crate::hash::{base_2b, Hash, HashSuite};
use crate::params::*;
use crate::wots::*;

// ------------------------------- XMSS ------------------------------------

pub fn xmss_node<S: HashSuite>(
    sk_seed: &[u8],
    node_index: u32,
    node_height: usize,
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Hash {
    if node_height == 0 {
        adrs.set_payload0(node_index);
        return wots_tw_pubkey_gen::<S>(sk_seed, pk_seed, adrs);
    }
    let l = xmss_node::<S>(sk_seed, 2 * node_index, node_height - 1, pk_seed, adrs);
    let r = xmss_node::<S>(sk_seed, 2 * node_index + 1, node_height - 1, pk_seed, adrs);
    adrs.set_type(SL_XMSS_TREE).zero_payload0();
    adrs.set_payload1(node_height as u32)
        .set_payload2(node_index);
    S::h(pk_seed, adrs, &l, &r)
}

pub fn xmss_sign<S: HashSuite>(
    message: &[u8],
    sk_seed: &[u8],
    keypair: u32,
    pk_seed: &[u8],
    adrs: &mut Adrs,
    p: &SlhParams,
) -> Vec<u8> {
    adrs.set_payload0(keypair);
    let mut sig = wots_tw_sign::<S>(message, sk_seed, pk_seed, adrs);
    for j in 0..p.h_prime {
        let sibling = (keypair >> j) ^ 1;
        sig.extend_from_slice(&xmss_node::<S>(sk_seed, sibling, j, pk_seed, adrs));
    }
    sig
}

pub fn xmss_pubkey_from_sig<S: HashSuite>(
    keypair: u32,
    sig: &[u8],
    message: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    p: &SlhParams,
) -> Hash {
    let (wots_sig, auth) = sig.split_at(WOTS_TW_CHAINS_SIZE);
    adrs.set_payload0(keypair);
    let mut node = wots_tw_pubkey_from_sig::<S>(wots_sig, message, pk_seed, adrs);
    adrs.set_type(SL_XMSS_TREE).zero_payload0();
    for k in 0..p.h_prime {
        adrs.set_payload1((k + 1) as u32)
            .set_payload2(keypair >> (k + 1));
        let sib = &auth[k * N..(k + 1) * N];
        node = if (keypair >> k) & 1 == 1 {
            S::h(pk_seed, adrs, sib, &node)
        } else {
            S::h(pk_seed, adrs, &node, sib)
        };
    }
    node
}

// ----------------------------- hypertree ---------------------------------

pub fn hypertree_sign<S: HashSuite>(
    message: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    mut tree: u64,
    mut leaf: u32,
    p: &SlhParams,
) -> Vec<u8> {
    let mut adrs = Adrs::new();
    let mut sig = Vec::with_capacity(p.d * p.xmss_signature_size());
    let mut msg: Vec<u8> = message.to_vec();
    for j in 0..p.d {
        adrs.set_layer(j as u8).set_tree_address(tree);
        let layer = xmss_sign::<S>(&msg, sk_seed, leaf, pk_seed, &mut adrs, p);
        if j < p.d - 1 {
            msg = xmss_pubkey_from_sig::<S>(leaf, &layer, &msg, pk_seed, &mut adrs, p).to_vec();
            leaf = (tree % (1 << p.h_prime)) as u32;
            tree >>= p.h_prime;
        }
        sig.extend_from_slice(&layer);
    }
    sig
}

pub fn hypertree_verify<S: HashSuite>(
    message: &[u8],
    sig: &[u8],
    pk_seed: &[u8],
    mut tree: u64,
    mut leaf: u32,
    sl_root: &[u8],
    p: &SlhParams,
) -> bool {
    let mut adrs = Adrs::new();
    let mut msg: Vec<u8> = message.to_vec();
    for j in 0..p.d {
        adrs.set_layer(j as u8).set_tree_address(tree);
        let layer = &sig[j * p.xmss_signature_size()..(j + 1) * p.xmss_signature_size()];
        msg = xmss_pubkey_from_sig::<S>(leaf, layer, &msg, pk_seed, &mut adrs, p).to_vec();
        if j < p.d - 1 {
            leaf = (tree % (1 << p.h_prime)) as u32;
            tree >>= p.h_prime;
        }
    }
    msg == sl_root
}

// -------------------------------- FORS -----------------------------------

fn fors_sk_gen<S: HashSuite>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    node_index: u32,
) -> Hash {
    adrs.set_type(SL_FORS_PRF)
        .set_payload1(0)
        .set_payload2(node_index);
    S::prf(pk_seed, sk_seed, adrs)
}

fn fors_node<S: HashSuite>(
    sk_seed: &[u8],
    node_index: u32,
    node_height: usize,
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Hash {
    if node_height == 0 {
        let pre = fors_sk_gen::<S>(sk_seed, pk_seed, adrs, node_index);
        adrs.set_type(SL_FORS_TREE)
            .set_payload1(0)
            .set_payload2(node_index);
        return S::f(pk_seed, adrs, &pre);
    }
    let l = fors_node::<S>(sk_seed, 2 * node_index, node_height - 1, pk_seed, adrs);
    let r = fors_node::<S>(sk_seed, 2 * node_index + 1, node_height - 1, pk_seed, adrs);
    adrs.set_type(SL_FORS_TREE)
        .set_payload1(node_height as u32)
        .set_payload2(node_index);
    S::h(pk_seed, adrs, &l, &r)
}

pub fn fors_sign<S: HashSuite>(
    digest: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    p: &SlhParams,
) -> Vec<u8> {
    let idx = base_2b(digest, p.a, p.k);
    let mut sig = Vec::with_capacity(p.fors_signature_size());
    for (i, &index) in idx.iter().enumerate() {
        let leaf = (i as u32) * (1 << p.a) + index;
        sig.extend_from_slice(&fors_sk_gen::<S>(sk_seed, pk_seed, adrs, leaf));
        for j in 0..p.a {
            let sib = (i as u32) * (1 << (p.a - j)) + ((index >> j) ^ 1);
            sig.extend_from_slice(&fors_node::<S>(sk_seed, sib, j, pk_seed, adrs));
        }
    }
    sig
}

pub fn fors_pubkey_from_sig<S: HashSuite>(
    sig: &[u8],
    digest: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
    p: &SlhParams,
) -> Hash {
    let idx = base_2b(digest, p.a, p.k);
    let mut offset = 0usize;
    let mut roots = Vec::with_capacity(p.k * N);
    for (i, &index) in idx.iter().enumerate() {
        let pre = &sig[offset..offset + N];
        offset += N;
        let tree_index = (i as u32) * (1 << p.a) + index;
        adrs.set_type(SL_FORS_TREE)
            .set_payload1(0)
            .set_payload2(tree_index);
        let mut node = S::f(pk_seed, adrs, pre);
        for j in 0..p.a {
            adrs.set_payload1((j + 1) as u32)
                .set_payload2(tree_index >> (j + 1));
            let sib = &sig[offset..offset + N];
            offset += N;
            node = if (index >> j) & 1 == 1 {
                S::h(pk_seed, adrs, sib, &node)
            } else {
                S::h(pk_seed, adrs, &node, sib)
            };
        }
        roots.extend_from_slice(&node);
    }
    adrs.set_type(SL_FORS_ROOTS).zero_payload12();
    S::t(pk_seed, adrs, &[&roots])
}

// ------------------------------ SLH-DSA ----------------------------------

fn digest_message<S: HashSuite>(
    r: &[u8],
    pk_seed: &[u8],
    sl_root: &[u8],
    m: &[&[u8]],
    p: &SlhParams,
) -> (Vec<u8>, u64, u32) {
    let digest = S::h_msg_sl(r, pk_seed, sl_root, m, p.m());
    let fors_digest = digest[..p.fors_digest_size()].to_vec();
    let mut off = p.fors_digest_size();
    let tlen = p.tree_index_bits().div_ceil(8);
    let tree_bytes = &digest[off..off + tlen];
    off += tlen;
    let llen = p.h_prime.div_ceil(8);
    let leaf_bytes = &digest[off..off + llen];
    let to_int = |b: &[u8]| b.iter().fold(0u128, |a, &x| (a << 8) | x as u128);
    let tree = (to_int(tree_bytes) % (1u128 << p.tree_index_bits())) as u64;
    let leaf = (to_int(leaf_bytes) % (1u128 << p.h_prime)) as u32;
    (fors_digest, tree, leaf)
}

/// Signs `message` with the context prefix FIPS 205 puts on external calls.
#[allow(clippy::too_many_arguments)]
pub fn slh_dsa_sign<S: HashSuite>(
    message: &[&[u8]],
    ctx: &[u8],
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    sl_root: &[u8],
    opt_rand: Option<&[u8]>,
    p: &SlhParams,
) -> Vec<u8> {
    assert!(ctx.len() < 256);
    let prefix = [0u8, ctx.len() as u8];
    let mut m: Vec<&[u8]> = vec![&prefix, ctx];
    m.extend_from_slice(message);
    slh_dsa_sign_internal::<S>(&m, sk_seed, sk_prf, pk_seed, sl_root, opt_rand, p)
}

/// The internal form: signs exactly the bytes given, with no context prefix.
/// This is what FIPS 205 calls `slh_sign_internal`, and what NIST's ACVP
/// vectors exercise.
#[allow(clippy::too_many_arguments)]
pub fn slh_dsa_sign_internal<S: HashSuite>(
    m: &[&[u8]],
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    sl_root: &[u8],
    opt_rand: Option<&[u8]>,
    p: &SlhParams,
) -> Vec<u8> {
    let r = S::prf_msg_sl(sk_prf, opt_rand.unwrap_or(pk_seed), m);
    let (fors_digest, tree, leaf) = digest_message::<S>(&r, pk_seed, sl_root, m, p);
    let mut adrs = Adrs::new();
    adrs.set_tree_address(tree).set_payload0(leaf);
    let fors_sig = fors_sign::<S>(&fors_digest, sk_seed, pk_seed, &mut adrs, p);
    let fors_pk = fors_pubkey_from_sig::<S>(&fors_sig, &fors_digest, pk_seed, &mut adrs, p);
    let ht = hypertree_sign::<S>(&fors_pk, sk_seed, pk_seed, tree, leaf, p);
    let mut out = Vec::with_capacity(p.signature_size());
    out.extend_from_slice(&r);
    out.extend_from_slice(&fors_sig);
    out.extend_from_slice(&ht);
    out
}

/// Verifies a signature made with the context prefix.
pub fn slh_dsa_verify<S: HashSuite>(
    message: &[&[u8]],
    sig: &[u8],
    ctx: &[u8],
    pk_seed: &[u8],
    sl_root: &[u8],
    p: &SlhParams,
) -> bool {
    if ctx.len() >= 256 {
        return false;
    }
    let prefix = [0u8, ctx.len() as u8];
    let mut m: Vec<&[u8]> = vec![&prefix, ctx];
    m.extend_from_slice(message);
    slh_dsa_verify_internal::<S>(&m, sig, pk_seed, sl_root, p)
}

/// The internal form, matching FIPS 205 `slh_verify_internal`.
pub fn slh_dsa_verify_internal<S: HashSuite>(
    m: &[&[u8]],
    sig: &[u8],
    pk_seed: &[u8],
    sl_root: &[u8],
    p: &SlhParams,
) -> bool {
    if sig.len() != p.signature_size() {
        return false;
    }
    let r = &sig[..N];
    let fors_sig = &sig[N..N + p.fors_signature_size()];
    let ht = &sig[N + p.fors_signature_size()..];
    let (fors_digest, tree, leaf) = digest_message::<S>(r, pk_seed, sl_root, m, p);
    let mut adrs = Adrs::new();
    adrs.set_tree_address(tree).set_payload0(leaf);
    let fors_pk = fors_pubkey_from_sig::<S>(fors_sig, &fors_digest, pk_seed, &mut adrs, p);
    hypertree_verify::<S>(&fors_pk, ht, pk_seed, tree, leaf, sl_root, p)
}
