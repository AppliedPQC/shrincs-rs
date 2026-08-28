//! The two one-time signatures.
//!
//! `wots_tw` is the classic checksum construction, used inside the stateless
//! fallback. `wots_c` replaces the checksum with a constant-sum constraint on
//! the chain indexes, which drops three chains and, more importantly, fixes
//! the verifier's work at `32*15 - 240 = 240` chain steps for every message.

use crate::adrs::*;
use crate::hash::{base_2b, f, h_grind, prf, t, Hash};
use crate::params::*;

fn chain(node: Hash, start: u32, steps: u32, pk_seed: &[u8], adrs: &mut Adrs, ty: u8) -> Hash {
    adrs.set_type(ty);
    let mut node = node;
    for j in start..start + steps {
        adrs.set_payload2(j);
        node = f(pk_seed, adrs, &node);
    }
    node
}

// =========================== WOTS-TW ====================================

/// 32 message indexes followed by 3 checksum indexes.
pub fn wots_tw_message_to_indexes(message: &[u8]) -> Vec<u32> {
    let mut idx = base_2b(message, WOTS_TW_CHAIN_BITS, WOTS_TW_CHAIN_COUNT1);
    let mut checksum = WOTS_TW_CHECKSUM_MAX - idx.iter().map(|&x| x as usize).sum::<usize>();
    let mut csum = [0u32; WOTS_TW_CHAIN_COUNT2];
    for i in 0..WOTS_TW_CHAIN_COUNT2 {
        csum[WOTS_TW_CHAIN_COUNT2 - 1 - i] = (checksum % (1 << WOTS_TW_CHAIN_BITS)) as u32;
        checksum >>= WOTS_TW_CHAIN_BITS;
    }
    idx.extend_from_slice(&csum);
    idx
}

pub fn wots_tw_pubkey_gen(sk_seed: &[u8], pk_seed: &[u8], adrs: &mut Adrs) -> Hash {
    let mut chains = Vec::with_capacity(WOTS_TW_CHAINS_SIZE);
    for i in 0..WOTS_TW_CHAIN_COUNT {
        adrs.set_type(SL_WOTS_TW_PRF)
            .set_payload1(i as u32)
            .set_payload2(0);
        let sk = prf(pk_seed, sk_seed, adrs);
        let end = chain(
            sk,
            0,
            (1 << WOTS_TW_CHAIN_BITS) - 1,
            pk_seed,
            adrs,
            SL_WOTS_TW_HASH,
        );
        chains.extend_from_slice(&end);
    }
    adrs.set_type(SL_WOTS_TW_PK).zero_payload12();
    t(pk_seed, adrs, &[&chains])
}

pub fn wots_tw_sign(message: &[u8], sk_seed: &[u8], pk_seed: &[u8], adrs: &mut Adrs) -> Vec<u8> {
    let idx = wots_tw_message_to_indexes(message);
    let mut sig = Vec::with_capacity(WOTS_TW_CHAINS_SIZE);
    for (i, &index) in idx.iter().enumerate() {
        adrs.set_type(SL_WOTS_TW_PRF)
            .set_payload1(i as u32)
            .set_payload2(0);
        let sk = prf(pk_seed, sk_seed, adrs);
        let v = chain(sk, 0, index, pk_seed, adrs, SL_WOTS_TW_HASH);
        sig.extend_from_slice(&v);
    }
    sig
}

pub fn wots_tw_pubkey_from_sig(
    sig: &[u8],
    message: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Hash {
    let idx = wots_tw_message_to_indexes(message);
    let mut chains = Vec::with_capacity(WOTS_TW_CHAINS_SIZE);
    for (i, &index) in idx.iter().enumerate() {
        adrs.set_payload1(i as u32);
        let steps = ((1 << WOTS_TW_CHAIN_BITS) - 1) - index;
        let mut node = [0u8; N];
        node.copy_from_slice(&sig[i * N..(i + 1) * N]);
        let end = chain(node, index, steps, pk_seed, adrs, SL_WOTS_TW_HASH);
        chains.extend_from_slice(&end);
    }
    adrs.set_type(SL_WOTS_TW_PK).zero_payload12();
    t(pk_seed, adrs, &[&chains])
}

// =========================== WOTS+C =====================================

/// Searches the 16-bit counter for a digest whose 32 chain indexes sum to
/// `WOTS_C_CONSTANT_SUM`. Succeeds after about 66 attempts on average; the
/// draft's parameters put the chance of exhausting all 2^16 below 2^-1450.
pub fn wots_c_grind(pk_seed: &[u8], digest: &[u8], adrs: &mut Adrs) -> Option<(u16, Vec<u32>)> {
    adrs.set_type(SF_WOTS_C_GRIND);
    for i in 0..=u16::MAX {
        let hashed = h_grind(pk_seed, adrs, digest, i);
        let idx = base_2b(&hashed, WOTS_C_CHAIN_BITS, WOTS_C_CHAIN_COUNT);
        if idx.iter().map(|&x| x as usize).sum::<usize>() == WOTS_C_CONSTANT_SUM {
            return Some((i, idx));
        }
    }
    None
}

/// Recomputes the indexes a counter claims, and rejects any that miss the sum.
pub fn wots_c_map_digest(
    pk_seed: &[u8],
    digest: &[u8],
    adrs: &mut Adrs,
    counter: u16,
) -> Option<Vec<u32>> {
    adrs.set_type(SF_WOTS_C_GRIND);
    let idx = base_2b(
        &h_grind(pk_seed, adrs, digest, counter),
        WOTS_C_CHAIN_BITS,
        WOTS_C_CHAIN_COUNT,
    );
    (idx.iter().map(|&x| x as usize).sum::<usize>() == WOTS_C_CONSTANT_SUM).then_some(idx)
}

pub fn wots_c_pubkey_gen(sk_seed: &[u8], pk_seed: &[u8], adrs: &mut Adrs) -> Hash {
    let structure = adrs.structure();
    let mut chains = Vec::with_capacity(WOTS_C_CHAINS_SIZE);
    for i in 0..WOTS_C_CHAIN_COUNT {
        adrs.set_type(SF_WOTS_C_PRF)
            .set_structure(structure)
            .set_payload1(i as u32)
            .set_payload2(0);
        let sk = prf(pk_seed, sk_seed, adrs);
        adrs.zero_payload0();
        let end = chain(
            sk,
            0,
            (1 << WOTS_C_CHAIN_BITS) - 1,
            pk_seed,
            adrs,
            SF_WOTS_C_HASH,
        );
        chains.extend_from_slice(&end);
    }
    adrs.set_type(SF_WOTS_C_PK).zero_payload12();
    t(pk_seed, adrs, &[&chains])
}

pub fn wots_c_sign(
    digest: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Option<Vec<u8>> {
    let (counter, idx) = wots_c_grind(pk_seed, digest, adrs)?;
    let structure = adrs.structure();
    let mut sig = Vec::with_capacity(2 + WOTS_C_CHAINS_SIZE);
    sig.extend_from_slice(&counter.to_be_bytes());
    for (i, &index) in idx.iter().enumerate() {
        adrs.set_type(SF_WOTS_C_PRF)
            .set_structure(structure)
            .set_payload1(i as u32)
            .set_payload2(0);
        let sk = prf(pk_seed, sk_seed, adrs);
        adrs.zero_payload0();
        let v = chain(sk, 0, index, pk_seed, adrs, SF_WOTS_C_HASH);
        sig.extend_from_slice(&v);
    }
    Some(sig)
}

pub fn wots_c_pubkey_from_sig(
    sig: &[u8],
    digest: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Option<Hash> {
    let counter = u16::from_be_bytes([sig[0], sig[1]]);
    let idx = wots_c_map_digest(pk_seed, digest, adrs, counter)?;
    let mut chains = Vec::with_capacity(WOTS_C_CHAINS_SIZE);
    adrs.zero_payload0();
    for (i, &index) in idx.iter().enumerate() {
        adrs.set_payload1(i as u32);
        let steps = ((1 << WOTS_C_CHAIN_BITS) - 1) - index;
        let mut node = [0u8; N];
        node.copy_from_slice(&sig[2 + i * N..2 + (i + 1) * N]);
        let end = chain(node, index, steps, pk_seed, adrs, SF_WOTS_C_HASH);
        chains.extend_from_slice(&end);
    }
    adrs.set_type(SF_WOTS_C_PK).zero_payload12();
    Some(t(pk_seed, adrs, &[&chains]))
}
