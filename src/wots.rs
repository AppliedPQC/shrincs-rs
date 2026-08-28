//! The two one-time signatures, over their one real difference.
//!
//! A Winternitz signature is the same machinery either way: derive a secret per
//! chain, walk each chain to the index the digest dictates, and let the
//! verifier walk the rest. What separates WOTS-TW from WOTS+C is only how the
//! digest becomes those indexes, and that is what [`WotsVariant`] captures.
//!
//! * [`WotsTw`] appends three checksum chains, so raising a message index
//!   forces a checksum index down, which would mean inverting a chain.
//! * [`WotsC`] appends nothing and instead admits only index vectors summing
//!   to [`WOTS_C_CONSTANT_SUM`], found by grinding a counter that the signature
//!   then carries. Raising one index requires lowering another, and the number
//!   of chain steps a verifier walks becomes fixed at `32*15 - 240 = 240` for
//!   every message, which is what lets consensus price the worst case.
//!
//! The spec-named functions below are thin wrappers over the shared core, so
//! the code still reads beside the draft while the walking logic exists once.

use crate::adrs::*;
use crate::hash::{base_2b, Hash, HashSuite};
use crate::params::*;

fn chain<S: HashSuite>(
    node: Hash,
    start: u32,
    steps: u32,
    pk_seed: &[u8],
    adrs: &mut Adrs,
    ty: u8,
) -> Hash {
    adrs.set_type(ty);
    let mut node = node;
    for j in start..start + steps {
        adrs.set_payload2(j);
        node = S::f(pk_seed, adrs, &node);
    }
    node
}

/// What distinguishes one Winternitz variant from another.
pub trait WotsVariant {
    const CHAIN_COUNT: usize;
    const CHAIN_BITS: usize;
    /// Address types for chain steps, for compressing the chain ends, and for
    /// deriving the chain secrets.
    const T_HASH: u8;
    const T_PK: u8;
    const T_PRF: u8;
    /// Bytes the signature carries ahead of the chain values.
    const PREFIX: usize;

    fn chains_size() -> usize {
        Self::CHAIN_COUNT * N
    }
    fn max_index() -> u32 {
        (1 << Self::CHAIN_BITS) - 1
    }

    /// Derives the secret for chain `i`.
    ///
    /// `structure` is read by the caller once, before any chain is walked. It
    /// has to be: WOTS+C clears the payload after each derivation, so by the
    /// second chain the address no longer carries it.
    fn secret<S: HashSuite>(
        sk_seed: &[u8],
        pk_seed: &[u8],
        adrs: &mut Adrs,
        i: u32,
        structure: [u8; 2],
    ) -> Hash;

    /// Signer side: the chain indexes, and the prefix a verifier needs to
    /// recover them. `None` only where a variant can fail to encode.
    fn encode_sign<S: HashSuite>(
        pk_seed: &[u8],
        digest: &[u8],
        adrs: &mut Adrs,
    ) -> Option<(Vec<u8>, Vec<u32>)>;

    /// Verifier side: the same indexes, from the digest and that prefix.
    fn encode_verify<S: HashSuite>(
        pk_seed: &[u8],
        digest: &[u8],
        adrs: &mut Adrs,
        prefix: &[u8],
    ) -> Option<Vec<u32>>;

    /// Puts the address into the state chain iteration expects before
    /// verification walks it. Only WOTS+C needs this: its signer left tree
    /// structure bytes in the payload and iterated the chains after clearing
    /// them. WOTS-TW must *not* clear it, because the caller put the XMSS
    /// keypair index in that field and the chain hashes depend on it.
    fn prepare_verify(_adrs: &mut Adrs) {}
}

// ------------------------- the shared machinery -------------------------

/// Walks every chain to its end. The public key is the compression of those
/// ends, which is what a Merkle leaf holds.
pub fn pubkey_gen<S: HashSuite, V: WotsVariant>(
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Hash {
    let structure = adrs.structure();
    let mut chains = Vec::with_capacity(V::chains_size());
    for i in 0..V::CHAIN_COUNT {
        let sk = V::secret::<S>(sk_seed, pk_seed, adrs, i as u32, structure);
        chains.extend_from_slice(&chain::<S>(sk, 0, V::max_index(), pk_seed, adrs, V::T_HASH));
    }
    adrs.set_type(V::T_PK).zero_payload12();
    S::t(pk_seed, adrs, &[&chains])
}

/// Walks each chain to the index the digest dictates, stopping there.
pub fn sign<S: HashSuite, V: WotsVariant>(
    digest: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Option<Vec<u8>> {
    let structure = adrs.structure();
    let (prefix, idx) = V::encode_sign::<S>(pk_seed, digest, adrs)?;
    debug_assert_eq!(prefix.len(), V::PREFIX);
    let mut sig = Vec::with_capacity(V::PREFIX + V::chains_size());
    sig.extend_from_slice(&prefix);
    for (i, &index) in idx.iter().enumerate() {
        let sk = V::secret::<S>(sk_seed, pk_seed, adrs, i as u32, structure);
        sig.extend_from_slice(&chain::<S>(sk, 0, index, pk_seed, adrs, V::T_HASH));
    }
    Some(sig)
}

/// Finishes each chain from where the signature stopped. Reaching the same
/// ends as `pubkey_gen` is what verification means here.
pub fn pubkey_from_sig<S: HashSuite, V: WotsVariant>(
    sig: &[u8],
    digest: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Option<Hash> {
    if sig.len() < V::PREFIX + V::chains_size() {
        return None;
    }
    let (prefix, values) = sig.split_at(V::PREFIX);
    let idx = V::encode_verify::<S>(pk_seed, digest, adrs, prefix)?;
    let mut chains = Vec::with_capacity(V::chains_size());
    V::prepare_verify(adrs);
    for (i, &index) in idx.iter().enumerate() {
        adrs.set_payload1(i as u32);
        let mut node = [0u8; N];
        node.copy_from_slice(&values[i * N..(i + 1) * N]);
        let steps = V::max_index() - index;
        chains.extend_from_slice(&chain::<S>(node, index, steps, pk_seed, adrs, V::T_HASH));
    }
    adrs.set_type(V::T_PK).zero_payload12();
    Some(S::t(pk_seed, adrs, &[&chains]))
}

// =============================== WOTS-TW ================================

/// The checksum variant, used inside the stateless fallback.
pub struct WotsTw;

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

impl WotsVariant for WotsTw {
    const CHAIN_COUNT: usize = WOTS_TW_CHAIN_COUNT;
    const CHAIN_BITS: usize = WOTS_TW_CHAIN_BITS;
    const T_HASH: u8 = SL_WOTS_TW_HASH;
    const T_PK: u8 = SL_WOTS_TW_PK;
    const T_PRF: u8 = SL_WOTS_TW_PRF;
    const PREFIX: usize = 0;

    fn secret<S: HashSuite>(
        sk_seed: &[u8],
        pk_seed: &[u8],
        adrs: &mut Adrs,
        i: u32,
        _structure: [u8; 2],
    ) -> Hash {
        adrs.set_type(Self::T_PRF).set_payload1(i).set_payload2(0);
        S::prf(pk_seed, sk_seed, adrs)
    }

    fn encode_sign<S: HashSuite>(
        _pk_seed: &[u8],
        digest: &[u8],
        _adrs: &mut Adrs,
    ) -> Option<(Vec<u8>, Vec<u32>)> {
        Some((Vec::new(), wots_tw_message_to_indexes(digest)))
    }

    fn encode_verify<S: HashSuite>(
        _pk_seed: &[u8],
        digest: &[u8],
        _adrs: &mut Adrs,
        _prefix: &[u8],
    ) -> Option<Vec<u32>> {
        Some(wots_tw_message_to_indexes(digest))
    }
}

pub fn wots_tw_pubkey_gen<S: HashSuite>(sk_seed: &[u8], pk_seed: &[u8], adrs: &mut Adrs) -> Hash {
    pubkey_gen::<S, WotsTw>(sk_seed, pk_seed, adrs)
}

pub fn wots_tw_sign<S: HashSuite>(
    message: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Vec<u8> {
    sign::<S, WotsTw>(message, sk_seed, pk_seed, adrs).expect("WOTS-TW encoding cannot fail")
}

pub fn wots_tw_pubkey_from_sig<S: HashSuite>(
    sig: &[u8],
    message: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Hash {
    pubkey_from_sig::<S, WotsTw>(sig, message, pk_seed, adrs).expect("WOTS-TW encoding cannot fail")
}

// =============================== WOTS+C =================================

/// The constant-sum variant, used by the stateful path.
pub struct WotsC;

/// Searches the 16-bit counter for a digest whose 32 chain indexes sum to
/// `WOTS_C_CONSTANT_SUM`. Succeeds after about 66 attempts on average; the
/// draft's parameters put the chance of exhausting all 2^16 below 2^-1450.
pub fn wots_c_grind<S: HashSuite>(
    pk_seed: &[u8],
    digest: &[u8],
    adrs: &mut Adrs,
) -> Option<(u16, Vec<u32>)> {
    adrs.set_type(SF_WOTS_C_GRIND);
    for i in 0..=u16::MAX {
        let hashed = S::h_grind(pk_seed, adrs, digest, i);
        let idx = base_2b(&hashed, WOTS_C_CHAIN_BITS, WOTS_C_CHAIN_COUNT);
        if idx.iter().map(|&x| x as usize).sum::<usize>() == WOTS_C_CONSTANT_SUM {
            return Some((i, idx));
        }
    }
    None
}

/// Recomputes the indexes a counter claims, and rejects any that miss the sum.
pub fn wots_c_map_digest<S: HashSuite>(
    pk_seed: &[u8],
    digest: &[u8],
    adrs: &mut Adrs,
    counter: u16,
) -> Option<Vec<u32>> {
    adrs.set_type(SF_WOTS_C_GRIND);
    let idx = base_2b(
        &S::h_grind(pk_seed, adrs, digest, counter),
        WOTS_C_CHAIN_BITS,
        WOTS_C_CHAIN_COUNT,
    );
    (idx.iter().map(|&x| x as usize).sum::<usize>() == WOTS_C_CONSTANT_SUM).then_some(idx)
}

impl WotsVariant for WotsC {
    const CHAIN_COUNT: usize = WOTS_C_CHAIN_COUNT;
    const CHAIN_BITS: usize = WOTS_C_CHAIN_BITS;
    const T_HASH: u8 = SF_WOTS_C_HASH;
    const T_PK: u8 = SF_WOTS_C_PK;
    const T_PRF: u8 = SF_WOTS_C_PRF;
    /// The two-byte grinding counter.
    const PREFIX: usize = 2;

    /// Note the structure bytes going in and the payload being cleared after.
    /// The address `PRF` sees carries the tree shape; the address the chain
    /// iteration sees does not, which is why a verifier never needs the shape.
    fn secret<S: HashSuite>(
        sk_seed: &[u8],
        pk_seed: &[u8],
        adrs: &mut Adrs,
        i: u32,
        structure: [u8; 2],
    ) -> Hash {
        adrs.set_type(Self::T_PRF)
            .set_structure(structure)
            .set_payload1(i)
            .set_payload2(0);
        let sk = S::prf(pk_seed, sk_seed, adrs);
        adrs.zero_payload0();
        sk
    }

    fn encode_sign<S: HashSuite>(
        pk_seed: &[u8],
        digest: &[u8],
        adrs: &mut Adrs,
    ) -> Option<(Vec<u8>, Vec<u32>)> {
        let (counter, idx) = wots_c_grind::<S>(pk_seed, digest, adrs)?;
        Some((counter.to_be_bytes().to_vec(), idx))
    }

    fn encode_verify<S: HashSuite>(
        pk_seed: &[u8],
        digest: &[u8],
        adrs: &mut Adrs,
        prefix: &[u8],
    ) -> Option<Vec<u32>> {
        wots_c_map_digest::<S>(
            pk_seed,
            digest,
            adrs,
            u16::from_be_bytes([prefix[0], prefix[1]]),
        )
    }

    fn prepare_verify(adrs: &mut Adrs) {
        adrs.zero_payload0();
    }
}

pub fn wots_c_pubkey_gen<S: HashSuite>(sk_seed: &[u8], pk_seed: &[u8], adrs: &mut Adrs) -> Hash {
    pubkey_gen::<S, WotsC>(sk_seed, pk_seed, adrs)
}

pub fn wots_c_sign<S: HashSuite>(
    digest: &[u8],
    sk_seed: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Option<Vec<u8>> {
    sign::<S, WotsC>(digest, sk_seed, pk_seed, adrs)
}

pub fn wots_c_pubkey_from_sig<S: HashSuite>(
    sig: &[u8],
    digest: &[u8],
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Option<Hash> {
    pubkey_from_sig::<S, WotsC>(sig, digest, pk_seed, adrs)
}
