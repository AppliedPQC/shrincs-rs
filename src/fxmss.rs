//! The stateful tree: a Merkle tree whose shape the signer chooses and the
//! verifier never learns.
//!
//! The root sits at the imaginary height 255, so a leaf at depth `d` has
//! height `255 - d` and that depth travels in one signature byte. A verifier
//! reads the byte, checks the authentication path is exactly `depth` siblings,
//! and climbs; nothing in that walk consults the shape. The shape instead
//! enters key derivation, through the two structure bytes that `PRF` sees.

use crate::adrs::*;
use crate::hash::{Hash, HashSuite};
use crate::params::*;
use crate::wots::{wots_c_pubkey_from_sig, wots_c_pubkey_gen, wots_c_sign};

/// Shifting a `u64` by 64 or more is undefined in Rust but well defined in the
/// specification's integer model, where the result is zero. FXMSS depths reach
/// 255, so every index shift goes through here.
#[inline]
fn shr(x: u64, n: u32) -> u64 {
    if n >= 64 {
        0
    } else {
        x >> n
    }
}

/// Is `leaf_index` representable at this depth?
pub fn index_fits(leaf_index: u64, leaf_depth: u32) -> bool {
    leaf_depth >= 64 || leaf_index < (1u64 << leaf_depth)
}

fn is_leaf(structure: [u8; 2], node_depth: u32, node_index: u64) -> bool {
    let (shape, depth) = (structure[0], structure[1] as u32);
    match shape {
        FXMSS_SHAPE_UNBALANCED => node_index == 1 || node_depth == depth,
        FXMSS_SHAPE_BALANCED => node_depth == depth,
        _ => false,
    }
}

pub fn fxmss_node<S: HashSuite>(
    sk_seed: &[u8],
    node_index: u64,
    node_height: u8,
    pk_seed: &[u8],
    structure: [u8; 2],
    adrs: &mut Adrs,
) -> Hash {
    let node_depth = (FXMSS_HEIGHT - node_height) as u32;
    if is_leaf(structure, node_depth, node_index) {
        adrs.set_node_height(node_height).set_node_index(node_index);
        adrs.zero_payload0().set_structure(structure);
        return wots_c_pubkey_gen::<S>(sk_seed, pk_seed, adrs);
    }
    let l = fxmss_node::<S>(
        sk_seed,
        2 * node_index,
        node_height - 1,
        pk_seed,
        structure,
        adrs,
    );
    let r = fxmss_node::<S>(
        sk_seed,
        2 * node_index + 1,
        node_height - 1,
        pk_seed,
        structure,
        adrs,
    );
    adrs.set_node_height(node_height).set_node_index(node_index);
    adrs.set_type(SF_FXMSS_TREE).zero_payload();
    S::h(pk_seed, adrs, &l, &r)
}

pub fn fxmss_sign<S: HashSuite>(
    digest: &[u8],
    sk_seed: &[u8],
    leaf_index: u64,
    leaf_height: u8,
    pk_seed: &[u8],
    structure: [u8; 2],
) -> Option<Vec<u8>> {
    let leaf_depth = (FXMSS_HEIGHT - leaf_height) as u32;
    let mut adrs = Adrs::new();
    adrs.set_node_height(leaf_height).set_node_index(leaf_index);
    adrs.zero_payload0().set_structure(structure);
    let mut sig = wots_c_sign::<S>(digest, sk_seed, pk_seed, &mut adrs)?;
    for j in 0..leaf_depth {
        let sibling = shr(leaf_index, j) ^ 1;
        let sibling_height = (leaf_height as u32 + j) as u8;
        sig.extend_from_slice(&fxmss_node::<S>(
            sk_seed,
            sibling,
            sibling_height,
            pk_seed,
            structure,
            &mut adrs,
        ));
    }
    Some(sig)
}

/// The whole verifier. It is given a leaf index, a height and the signature,
/// and never the tree shape: one code path covers UXMSS, BXMSS and anything
/// else a signer builds.
pub fn fxmss_pubkey_from_sig<S: HashSuite>(
    leaf_index: u64,
    leaf_height: u8,
    sig: &[u8],
    digest: &[u8],
    pk_seed: &[u8],
) -> Option<Hash> {
    let leaf_depth = (FXMSS_HEIGHT - leaf_height) as u32;
    let head = 2 + WOTS_C_CHAINS_SIZE;
    if sig.len() != head + (leaf_depth as usize) * N || !index_fits(leaf_index, leaf_depth) {
        return None;
    }
    let (wots_sig, auth) = sig.split_at(head);
    let mut adrs = Adrs::new();
    adrs.set_node_height(leaf_height).set_node_index(leaf_index);
    let mut node = wots_c_pubkey_from_sig::<S>(wots_sig, digest, pk_seed, &mut adrs)?;
    adrs.set_type(SF_FXMSS_TREE).zero_payload();
    for k in 0..leaf_depth {
        adrs.set_node_height(adrs.node_height() + 1);
        adrs.set_node_index(shr(leaf_index, k + 1));
        let sib = &auth[(k as usize) * N..((k as usize) + 1) * N];
        node = if shr(leaf_index, k) & 1 == 1 {
            S::h(pk_seed, &adrs, sib, &node)
        } else {
            S::h(pk_seed, &adrs, &node, sib)
        };
    }
    Some(node)
}

/// Which leaf the state counter selects, as `(index, height)`. `None` means
/// the budget is spent, which sends the signer to the stateless path rather
/// than failing.
pub fn leaf_select(structure: [u8; 2], state_ctr: u64) -> Option<(u64, u8)> {
    let (shape, depth) = (structure[0], structure[1]);
    if depth == 0 {
        return None;
    }
    match shape {
        FXMSS_SHAPE_UNBALANCED => {
            if state_ctr == depth as u64 {
                Some((0, FXMSS_HEIGHT - depth))
            } else if state_ctr < depth as u64 {
                Some((1, FXMSS_HEIGHT - 1 - state_ctr as u8))
            } else {
                None
            }
        }
        FXMSS_SHAPE_BALANCED => {
            let budget = if depth >= 64 { u64::MAX } else { 1u64 << depth };
            (state_ctr < budget).then(|| (state_ctr, FXMSS_HEIGHT - depth))
        }
        _ => None,
    }
}
