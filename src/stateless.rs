//! The stateless fallback: SLH-DSA under a non-standard parameter set.
//!
//! This is FIPS 205 unmodified apart from the parameters and the caller
//! supplying the randomiser, which is the point: the fallback inherits the
//! standard's analysis rather than asking for a new one.

use crate::adrs::*;
use crate::hash::*;
use crate::params::*;
use crate::wots::*;

// ------------------------------- XMSS ------------------------------------

pub fn xmss_node(
    sk_seed: &[u8],
    node_index: u32,
    node_height: usize,
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Hash {
    if node_height == 0 {
        adrs.set_payload0(node_index);
        return wots_tw_pubkey_gen(sk_seed, pk_seed, adrs);
    }
    let l = xmss_node(sk_seed, 2 * node_index, node_height - 1, pk_seed, adrs);
    let r = xmss_node(sk_seed, 2 * node_index + 1, node_height - 1, pk_seed, adrs);
    adrs.set_type(SL_XMSS_TREE).zero_payload0();
    adrs.set_payload1(node_height as u32)
        .set_payload2(node_index);
    h(pk_seed, adrs, &l, &r)
}

pub fn xmss_sign(
    message: &[u8],
    sk_seed: &[u8],
    keypair: u32,
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Vec<u8> {
    adrs.set_payload0(keypair);
    let mut sig = wots_tw_sign(message, sk_seed, pk_seed, adrs);
    for j in 0..SPHX_XMSS_HEIGHT {
        let sibling = (keypair >> j) ^ 1;
        sig.extend_from_slice(&xmss_node(sk_seed, sibling, j, pk_seed, adrs));
    }
    sig
}

pub fn xmss_pubkey_from_sig(
    keypair: u32,
    sig: &[u8],
    message: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Hash {
    let (wots_sig, auth) = sig.split_at(WOTS_TW_CHAINS_SIZE);
    adrs.set_payload0(keypair);
    let mut node = wots_tw_pubkey_from_sig(wots_sig, message, pk_seed, adrs);
    adrs.set_type(SL_XMSS_TREE).zero_payload0();
    for k in 0..SPHX_XMSS_HEIGHT {
        adrs.set_payload1((k + 1) as u32)
            .set_payload2(keypair >> (k + 1));
        let sib = &auth[k * N..(k + 1) * N];
        node = if (keypair >> k) & 1 == 1 {
            h(pk_seed, adrs, sib, &node)
        } else {
            h(pk_seed, adrs, &node, sib)
        };
    }
    node
}

// ----------------------------- hypertree ---------------------------------

pub fn hypertree_sign(
    message: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    mut tree: u64,
    mut leaf: u32,
) -> Vec<u8> {
    let mut adrs = Adrs::new();
    let mut sig = Vec::with_capacity(HYPERTREE_SIGNATURE_SIZE);
    let mut msg: Vec<u8> = message.to_vec();
    for j in 0..SPHX_LAYER_COUNT {
        adrs.set_layer(j as u8).set_tree_address(tree);
        let layer = xmss_sign(&msg, sk_seed, leaf, pk_seed, &mut adrs);
        if j < SPHX_LAYER_COUNT - 1 {
            msg = xmss_pubkey_from_sig(leaf, &layer, &msg, pk_seed, &mut adrs).to_vec();
            leaf = (tree % (1 << SPHX_XMSS_HEIGHT)) as u32;
            tree >>= SPHX_XMSS_HEIGHT;
        }
        sig.extend_from_slice(&layer);
    }
    sig
}

pub fn hypertree_verify(
    message: &[u8],
    sig: &[u8],
    pk_seed: &[u8],
    mut tree: u64,
    mut leaf: u32,
    sl_root: &[u8],
) -> bool {
    let mut adrs = Adrs::new();
    let mut msg: Vec<u8> = message.to_vec();
    for j in 0..SPHX_LAYER_COUNT {
        adrs.set_layer(j as u8).set_tree_address(tree);
        let layer = &sig[j * SPHX_XMSS_SIGNATURE_SIZE..(j + 1) * SPHX_XMSS_SIGNATURE_SIZE];
        msg = xmss_pubkey_from_sig(leaf, layer, &msg, pk_seed, &mut adrs).to_vec();
        if j < SPHX_LAYER_COUNT - 1 {
            leaf = (tree % (1 << SPHX_XMSS_HEIGHT)) as u32;
            tree >>= SPHX_XMSS_HEIGHT;
        }
    }
    msg == sl_root
}

// -------------------------------- FORS -----------------------------------

fn fors_sk_gen(sk_seed: &[u8], pk_seed: &[u8], adrs: &mut Adrs, node_index: u32) -> Hash {
    adrs.set_type(SL_FORS_PRF)
        .set_payload1(0)
        .set_payload2(node_index);
    prf(pk_seed, sk_seed, adrs)
}

fn fors_node(
    sk_seed: &[u8],
    node_index: u32,
    node_height: usize,
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Hash {
    if node_height == 0 {
        let pre = fors_sk_gen(sk_seed, pk_seed, adrs, node_index);
        adrs.set_type(SL_FORS_TREE)
            .set_payload1(0)
            .set_payload2(node_index);
        return f(pk_seed, adrs, &pre);
    }
    let l = fors_node(sk_seed, 2 * node_index, node_height - 1, pk_seed, adrs);
    let r = fors_node(sk_seed, 2 * node_index + 1, node_height - 1, pk_seed, adrs);
    adrs.set_type(SL_FORS_TREE)
        .set_payload1(node_height as u32)
        .set_payload2(node_index);
    h(pk_seed, adrs, &l, &r)
}

pub fn fors_sign(digest: &[u8], sk_seed: &[u8], pk_seed: &[u8], adrs: &mut Adrs) -> Vec<u8> {
    let idx = base_2b(digest, SPHX_FORS_HEIGHT, SPHX_FORS_COUNT);
    let mut sig = Vec::with_capacity(FORS_SIGNATURE_SIZE);
    for (i, &index) in idx.iter().enumerate() {
        let leaf = (i as u32) * (1 << SPHX_FORS_HEIGHT) + index;
        sig.extend_from_slice(&fors_sk_gen(sk_seed, pk_seed, adrs, leaf));
        for j in 0..SPHX_FORS_HEIGHT {
            let sib = (i as u32) * (1 << (SPHX_FORS_HEIGHT - j)) + ((index >> j) ^ 1);
            sig.extend_from_slice(&fors_node(sk_seed, sib, j, pk_seed, adrs));
        }
    }
    sig
}

pub fn fors_pubkey_from_sig(sig: &[u8], digest: &[u8], pk_seed: &[u8], adrs: &mut Adrs) -> Hash {
    let idx = base_2b(digest, SPHX_FORS_HEIGHT, SPHX_FORS_COUNT);
    let mut offset = 0usize;
    let mut roots = Vec::with_capacity(SPHX_FORS_COUNT * N);
    for (i, &index) in idx.iter().enumerate() {
        let pre = &sig[offset..offset + N];
        offset += N;
        let tree_index = (i as u32) * (1 << SPHX_FORS_HEIGHT) + index;
        adrs.set_type(SL_FORS_TREE)
            .set_payload1(0)
            .set_payload2(tree_index);
        let mut node = f(pk_seed, adrs, pre);
        for j in 0..SPHX_FORS_HEIGHT {
            adrs.set_payload1((j + 1) as u32)
                .set_payload2(tree_index >> (j + 1));
            let sib = &sig[offset..offset + N];
            offset += N;
            node = if (index >> j) & 1 == 1 {
                h(pk_seed, adrs, sib, &node)
            } else {
                h(pk_seed, adrs, &node, sib)
            };
        }
        roots.extend_from_slice(&node);
    }
    adrs.set_type(SL_FORS_ROOTS).zero_payload12();
    t(pk_seed, adrs, &[&roots])
}

// ------------------------------ SLH-DSA ----------------------------------

fn digest_message(r: &[u8], pk_seed: &[u8], sl_root: &[u8], m: &[&[u8]]) -> (Vec<u8>, u64, u32) {
    let digest = h_msg_sl(r, pk_seed, sl_root, m);
    let fors_digest = digest[..FORS_DIGEST_SIZE].to_vec();
    let mut off = FORS_DIGEST_SIZE;
    let tlen = SPHX_TREE_INDEX_BITS.div_ceil(8);
    let tree_bytes = &digest[off..off + tlen];
    off += tlen;
    let llen = SPHX_XMSS_HEIGHT.div_ceil(8);
    let leaf_bytes = &digest[off..off + llen];
    let to_int = |b: &[u8]| b.iter().fold(0u128, |a, &x| (a << 8) | x as u128);
    let tree = (to_int(tree_bytes) % (1u128 << SPHX_TREE_INDEX_BITS)) as u64;
    let leaf = (to_int(leaf_bytes) % (1u128 << SPHX_XMSS_HEIGHT)) as u32;
    (fors_digest, tree, leaf)
}

pub fn slh_dsa_sign(
    message: &[&[u8]],
    ctx: &[u8],
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    sl_root: &[u8],
    opt_rand: Option<&[u8]>,
) -> Vec<u8> {
    assert!(ctx.len() < 256);
    let prefix = [0u8, ctx.len() as u8];
    let mut m: Vec<&[u8]> = vec![&prefix, ctx];
    m.extend_from_slice(message);
    let r = prf_msg_sl(sk_prf, opt_rand.unwrap_or(pk_seed), &m);
    let (fors_digest, tree, leaf) = digest_message(&r, pk_seed, sl_root, &m);
    let mut adrs = Adrs::new();
    adrs.set_tree_address(tree).set_payload0(leaf);
    let fors_sig = fors_sign(&fors_digest, sk_seed, pk_seed, &mut adrs);
    let fors_pk = fors_pubkey_from_sig(&fors_sig, &fors_digest, pk_seed, &mut adrs);
    let ht = hypertree_sign(&fors_pk, sk_seed, pk_seed, tree, leaf);
    let mut out = Vec::with_capacity(SPHX_SIGNATURE_SIZE);
    out.extend_from_slice(&r);
    out.extend_from_slice(&fors_sig);
    out.extend_from_slice(&ht);
    out
}

pub fn slh_dsa_verify(
    message: &[&[u8]],
    sig: &[u8],
    ctx: &[u8],
    pk_seed: &[u8],
    sl_root: &[u8],
) -> bool {
    if ctx.len() >= 256 || sig.len() != SPHX_SIGNATURE_SIZE {
        return false;
    }
    let prefix = [0u8, ctx.len() as u8];
    let mut m: Vec<&[u8]> = vec![&prefix, ctx];
    m.extend_from_slice(message);
    let r = &sig[..N];
    let fors_sig = &sig[N..N + FORS_SIGNATURE_SIZE];
    let ht = &sig[N + FORS_SIGNATURE_SIZE..];
    let (fors_digest, tree, leaf) = digest_message(r, pk_seed, sl_root, &m);
    let mut adrs = Adrs::new();
    adrs.set_tree_address(tree).set_payload0(leaf);
    let fors_pk = fors_pubkey_from_sig(fors_sig, &fors_digest, pk_seed, &mut adrs);
    hypertree_verify(&fors_pk, ht, pk_seed, tree, leaf, sl_root)
}
